//! I2P SAM control-protocol fuzzing scenario for Bitcoin Core.
//!
//! This fuzzes the **SAM proxy protocol parser itself** in `i2p.cpp` rather
//! than using SAM as plumbing to reach P2P. The fuzz input controls every
//! byte the (fake, in-process) SAM proxy sends back, so the bytes flowing
//! into the reply parser are attacker-controlled. Code under test:
//!
//!   * `Session::SendRequestAndGetReply` — receive + tokenize a reply
//!   * `Reply` keyword map construction (`Split(full, ' ')`, split on `=`)
//!   * `Reply::Get` (missing-key / valueless-key `runtime_error` paths)
//!   * `SwapBase64` / `DecodeI2PBase64` (bad Base64 -> throw)
//!   * `DestBinToAddr` -> `CNetAddr::SetSpecial` (bad address -> throw)
//!   * `MyDestination` certificate-length parsing (short key / oversized
//!     cert-length -> throw) on the transient `DESTINATION=` path
//!   * `SESSION CREATE` / `NAMING LOOKUP` / `STREAM CONNECT` result handling,
//!     including the `INVALID_ID` / `CANT_REACH_PEER` / `TIMEOUT` branches
//!     and the `CheckControlSock` / `Disconnect` teardown paths
//!
//! ## Reaching the parser within the snapshot model
//!
//! The fuzzamoto snapshot is taken inside `runner.get_fuzz_input()`, *after*
//! `Scenario::new` returns, so any SAM traffic required for the node to
//! finish starting up would have to be deterministic and could not consume
//! fuzz bytes. We avoid that entirely by running with
//! `-i2pacceptincoming=0`: `net.cpp` only constructs the persistent
//! `m_i2p_sam_session` when accept-incoming is enabled, so with it off there
//! is **no SAM traffic at all before the snapshot**.
//!
//! Every outbound I2P dial then builds a fresh **transient** session
//! (`Session(const Proxy&, ...)`), whose complete control exchange happens
//! post-snapshot and is fully fuzzed:
//!
//! ```text
//!   HELLO VERSION MIN=3.1 MAX=3.1
//!   SESSION CREATE STYLE=STREAM ID=.. DESTINATION=TRANSIENT SIGNATURE_TYPE=7 ...
//!   NAMING LOOKUP NAME=<addr>
//!   STREAM CONNECT ID=<id> DESTINATION=<dest> SILENT=false
//! ```
//!
//! Each test case triggers N outbound dials (`addnode <i2p> onetry`); the
//! proxy answers each SAM request with the next fuzz-controlled blob.
//!
//! ## Liveness
//!
//! `i2p.cpp` reads replies via `RecvUntilTerminator('\n', timeout, ...)`
//! (control timeout 3 min, `MAX_MSG_SIZE` 64 KiB). To keep throughput high
//! the proxy always appends exactly one `\n` to each blob and caps blob
//! length far below 64 KiB, so the parser never starves on a missing
//! terminator — the interesting bugs are in how the content up to the
//! terminator is handled, not in starvation. After the dials the node is
//! checked with `is_alive`; a crash/assert/hang in the I2P path fails the
//! case.

use fuzzamoto::{
    fuzzamoto_main,
    scenarios::{Scenario, ScenarioInput, ScenarioResult},
};

use corepc_node::{Conf, Node, P2P};

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

/// SAM 3.1 fixed virtual port. `i2p.cpp::Session::Connect` refuses any other
/// port, so the dialed I2P address must use it.
const I2P_SAM31_PORT: u16 = 0;

/// Hard cap on one fuzz-controlled reply blob — well below the 64 KiB
/// `MAX_MSG_SIZE` so a missing `\n` can never starve the parser (the proxy
/// always appends exactly one `\n`).
const MAX_REPLY_BLOB: usize = 4096;

/// Max SAM requests answered per control socket (defensive against the node
/// looping on one socket and exhausting the script).
const MAX_REQUESTS_PER_CONN: usize = 16;

// --------------------------------------------------------------------------
// Fuzz input
// --------------------------------------------------------------------------

/// One scripted reply: raw bytes the proxy sends for the next SAM request
/// (a single `\n` is always appended). If `promote` is set, after sending
/// the proxy treats the socket as a raw stream and stops parsing — emulating
/// a successful `STREAM CONNECT` so the post-connect `net.cpp` path is also
/// reached.
#[derive(Clone)]
struct Reply {
    blob: Vec<u8>,
    promote: bool,
}

struct TestCase {
    /// One lane per outbound dial / SAM control connection. `lanes[k]` is the
    /// ordered list of replies the proxy will serve to the k-th connection
    /// (request 0 -> HELLO reply, 1 -> SESSION CREATE reply, 2 -> NAMING
    /// LOOKUP reply, 3 -> STREAM CONNECT reply; beyond that a bare `\n`).
    lanes: Vec<Vec<Reply>>,
}

impl<'a> ScenarioInput<'a> for TestCase {
    /// Tolerant, length-prefixed wire format (truncation never errors — the
    /// decoder just stops early so the mutator can splice freely):
    ///
    /// ```text
    ///   u8        n_lanes        -> clamped to 1..=64 (one per dial)
    ///   n_lanes x {
    ///     u8      n_replies      -> clamped to 0..=8 (a transient session
    ///                               issues <=4 SAM requests; allow a little
    ///                               slack for session-recreate retries)
    ///     n_replies x {
    ///       u8     flags         (bit0 = promote)
    ///       u16 le blob_len      (clamped to MAX_REPLY_BLOB and to remaining)
    ///       blob_len blob
    ///     }
    ///   }
    /// ```
    ///
    /// The number of dials the scenario triggers is exactly `lanes.len()`, so
    /// dial *k* deterministically consumes lane *k* no matter how the dials
    /// interleave on the node's net thread.
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        // Plain cursor; no closure capturing it, so we can freely test
        // exhaustion (`pos >= bytes.len()`) alongside reads.
        let mut pos = 0usize;

        // Read up to `n` bytes, advancing the cursor. Never panics: a short
        // read just returns fewer bytes (possibly empty), so truncated fuzz
        // input is tolerated rather than erroring.
        fn take<'b>(bytes: &'b [u8], pos: &mut usize, n: usize) -> &'b [u8] {
            let start = (*pos).min(bytes.len());
            let end = (*pos + n).min(bytes.len());
            *pos = end;
            &bytes[start..end]
        }
        let byte = |bytes: &[u8], pos: &mut usize, default: u8| -> u8 {
            take(bytes, pos, 1).first().copied().unwrap_or(default)
        };

        let n_lanes = (usize::from(byte(bytes, &mut pos, 1)) % 64) + 1;

        let mut lanes: Vec<Vec<Reply>> = Vec::with_capacity(n_lanes);
        for _ in 0..n_lanes {
            // If input is exhausted, remaining lanes are empty (the proxy
            // then answers each request with a bare `\n`).
            let n_replies = usize::from(byte(bytes, &mut pos, 0)).min(8);
            let mut lane = Vec::with_capacity(n_replies);
            for _ in 0..n_replies {
                if pos >= bytes.len() {
                    break;
                }
                let flags = byte(bytes, &mut pos, 0);
                let lo = byte(bytes, &mut pos, 0);
                let hi = byte(bytes, &mut pos, 0);
                let want =
                    usize::from(u16::from_le_bytes([lo, hi])).min(MAX_REPLY_BLOB);
                let blob = take(bytes, &mut pos, want).to_vec();
                lane.push(Reply {
                    blob,
                    promote: flags & 1 != 0,
                });
            }
            lanes.push(lane);
        }

        Ok(TestCase { lanes })
    }
}

// --------------------------------------------------------------------------
// Fake SAM proxy whose replies are entirely fuzz-controlled
// --------------------------------------------------------------------------

/// The fuzz-derived plan for one whole test case.
///
/// Replies are split into independent **lanes**, one per SAM control
/// connection the node opens. Each accepted proxy connection atomically
/// claims the next lane via `conn_counter` and only ever serves that lane's
/// replies. This makes the outcome independent of the order/timing in which
/// concurrent `addnode` dials reach the proxy, so no inter-dial sleep is
/// needed for determinism: connection *k* always gets lane *k*'s bytes
/// regardless of how the net thread interleaves the dials.
struct Session {
    /// `lanes[k]` = the ordered replies for the k-th control connection.
    lanes: Vec<Vec<Reply>>,
    /// Index of the next lane to hand out (one per accepted connection).
    conn_counter: AtomicUsize,
    /// A connection sends `()` here exactly once, when its handler returns
    /// (script exhausted, `promote` socket closed, or node hung up). `run()`
    /// waits for one signal per expected connection instead of sleeping.
    done_tx: mpsc::Sender<()>,
}

impl Session {
    /// Claim the next lane for a freshly accepted connection. Connections
    /// beyond the number of lanes get an empty lane (proxy then only ever
    /// replies with bare `\n`, keeping the parser unblocked).
    fn claim_lane(&self) -> Vec<Reply> {
        let k = self.conn_counter.fetch_add(1, Ordering::SeqCst);
        self.lanes.get(k).cloned().unwrap_or_default()
    }
}

/// The proxy resolves the *current* session lazily per control connection
/// from this shared slot, so the scenario can install the fuzz-derived
/// session *after* the snapshot is taken (the proxy thread itself is started,
/// and captured by the snapshot, before any fuzz input exists).
type SessionSlot = Arc<Mutex<Option<Arc<Session>>>>;

fn spawn_sam_proxy(slot: SessionSlot) -> Result<SocketAddr, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| format!("bind fake SAM listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("SAM listener addr: {e}"))?;

    thread::Builder::new()
        .name("fuzzed-sam".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let slot = Arc::clone(&slot);
                thread::spawn(move || {
                    // Resolve the active session. If none is installed yet
                    // there is also no fuzz traffic, so a bare empty session
                    // (no completion signal) is correct.
                    let Some(session) = slot.lock().ok().and_then(|g| g.clone()) else {
                        return;
                    };
                    let lane = session.claim_lane();
                    let _ = handle_control_conn(stream, lane);
                    // Signal completion regardless of how the handler ended;
                    // a dropped receiver (run() already moved on) is fine.
                    let _ = session.done_tx.send(());
                });
            }
        })
        .map_err(|e| format!("spawn fuzzed SAM thread: {e}"))?;

    Ok(addr)
}

/// Read SAM requests line-by-line and answer each with the next reply from
/// this connection's lane (+ one `\n`). We deliberately do not parse/validate
/// the request — the node's parser is the target, not ours — we only detect
/// the `\n` that ends a request so reply timing matches a real proxy.
fn handle_control_conn(stream: TcpStream, lane: Vec<Reply>) -> std::io::Result<()> {
    let mut reader = stream.try_clone()?;
    let mut writer = stream;

    let mut buf = [0u8; 1024];
    let mut line: Vec<u8> = Vec::new();
    let mut served = 0usize;

    loop {
        if served >= MAX_REQUESTS_PER_CONN {
            return Ok(());
        }

        let n = match reader.read(&mut buf) {
            Ok(0) => return Ok(()),  // node closed the control socket
            Ok(n) => n,
            Err(_) => return Ok(()), // read timeout / socket gone
        };
        line.extend_from_slice(&buf[..n]);

        // Possibly several pipelined requests; answer each terminated one.
        while let Some(pos) = line.iter().position(|&b| b == b'\n') {
            let _request: Vec<u8> = line.drain(..=pos).collect();

            // The k-th request on this connection consumes lane[k]; once the
            // lane is exhausted we still send a bare `\n` so the parser gets
            // a terminator and the node makes forward progress.
            let reply = lane.get(served).cloned().unwrap_or(Reply {
                blob: Vec::new(),
                promote: false,
            });
            served += 1;

            let blob = if reply.blob.len() > MAX_REPLY_BLOB {
                &reply.blob[..MAX_REPLY_BLOB]
            } else {
                &reply.blob[..]
            };
            if writer.write_all(blob).is_err()
                || writer.write_all(b"\n").is_err()
                || writer.flush().is_err()
            {
                return Ok(());
            }

            if reply.promote {
                // Emulate a successful STREAM CONNECT/ACCEPT: the node now
                // treats this socket as a raw P2P stream. Drain & ignore so
                // the node never blocks on send; it will time the (silent)
                // peer out. This exercises the SAM success path + the
                // post-Connect plumbing in net.cpp.
                let mut sink = [0u8; 4096];
                loop {
                    match reader.read(&mut sink) {
                        Ok(0) | Err(_) => return Ok(()),
                        Ok(_) => {}
                    }
                }
            }

            if served >= MAX_REQUESTS_PER_CONN {
                return Ok(());
            }
        }
    }
}

// --------------------------------------------------------------------------
// Bitcoin Core node, configured so ALL SAM traffic is post-snapshot
// --------------------------------------------------------------------------

struct I2PNode {
    node: Node,
}

impl I2PNode {
    fn start(exe_path: &str, sam_addr: SocketAddr) -> Result<Self, String> {
        let mut conf = Conf::default();
        conf.tmpdir = None;
        conf.staticdir = None;
        conf.p2p = P2P::Yes;

        let i2psam = format!("-i2psam={sam_addr}");
/*
        #[cfg(feature = "inherit_stdout")]
        {
            conf.args.extend_from_slice(&[
                "-debug",
                "-debugexclude=libevent",
                "-debugexclude=leveldb",
            ]);
            conf.view_stdout = true;
        }
*/
        conf.args.extend_from_slice(&[
            "-txreconciliation",
            "-peerbloomfilters",
            "-peerblockfilters",
            "-blockfilterindex",
            "-par=4",
            "-rpcthreads=4",
            "-deprecatedrpc=create_bdb",
            "-keypool=10",
            "-listenonion=0",
            // I2P proxy set, accept-incoming OFF: net.cpp never builds the
            // persistent m_i2p_sam_session, so there is ZERO SAM traffic
            // before the snapshot. Every post-snapshot dial creates a fresh
            // transient session whose full SAM exchange is fuzz-driven.
            i2psam.as_str(),
            "-i2pacceptincoming=0",
            "-onlynet=i2p",
            "-maxmempool=5",
            "-dbcache=4",
            "-datacarriersize=1000000",
            "-peertimeout=999999999",
            "-noconnect",
        ]);

        let node = Node::with_conf(exe_path, &conf)
            .map_err(|e| format!("Failed to start I2P node: {e:?}"))?;
        Ok(Self { node })
    }

    fn is_alive(&self) -> Result<(), String> {
        let client = &self.node.client;
        client
            .call::<serde_json::Value>("echo", &["i2p-sam-alive".into()])
            .map_err(|e| format!("alive check failed: {e:?}"))?;
        client
            .call::<()>("syncwithvalidationinterfacequeue", &[])
            .map_err(|e| format!("sync validation queue: {e:?}"))?;
        Ok(())
    }
}

#[cfg(not(feature = "nyx"))]
impl Drop for I2PNode {
    fn drop(&mut self) {
        let _ = self.node.stop();
    }
}

// --------------------------------------------------------------------------
// Scenario
// --------------------------------------------------------------------------

struct I2PSamScenario {
    node: I2PNode,
    slot: SessionSlot,
}

impl I2PSamScenario {
    fn build(exe_path: &str) -> Result<Self, String> {
        // Proxy must be listening before the node starts so `-i2psam`
        // resolves; the slot is empty until `run()` installs a session (and
        // there is no SAM traffic before then anyway).
        let slot: SessionSlot = Arc::new(Mutex::new(None));
        let sam_addr = spawn_sam_proxy(Arc::clone(&slot))?;
        let node = I2PNode::start(exe_path, sam_addr)?;
        Ok(Self { node, slot })
    }
}

/// Build a syntactically valid, unique `.b32.i2p` address for dial `k`.
///
/// `CNetAddr::SetSpecial` accepts a 52-char lowercase base32 label followed
/// by `.b32.i2p`. We only need *syntactic* validity (the proxy intercepts the
/// NAMING LOOKUP), but each dial must be a *distinct* address or `addnode`
/// would reject the duplicate and no new SAM session would be created.
fn dial_addr(k: usize) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut label = [b'a'; 52];
    // Encode k into the first few base32 chars; rest stay 'a'. 52 base32
    // symbols of entropy is far more than the <=64 dials we ever do.
    let mut v = k;
    let mut i = 0;
    while v > 0 && i < label.len() {
        label[i] = A[v & 31];
        v >>= 5;
        i += 1;
    }
    // SAFETY: all bytes are ASCII base32.
    let label = std::str::from_utf8(&label).unwrap_or("a");
    format!("{label}.b32.i2p:{I2P_SAM31_PORT}")
}

impl<'a> Scenario<'a, TestCase> for I2PSamScenario {
    fn new(args: &[String]) -> Result<Self, String> {
        Self::build(&args[1])
    }

    fn run(&mut self, testcase: TestCase) -> ScenarioResult {
        let n_lanes = testcase.lanes.len();

        // 1. Install this case's fuzz-controlled session. One completion
        //    signal will be sent per proxy connection that the node opens.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let session = Arc::new(Session {
            lanes: testcase.lanes,
            conn_counter: AtomicUsize::new(0),
            done_tx,
        });
        if let Ok(mut g) = self.slot.lock() {
            *g = Some(Arc::clone(&session));
        }

        // 2. Trigger one outbound I2P dial per lane. Each `addnode
        //    <unique>.b32.i2p:0 onetry` makes net.cpp build a fresh transient
        //    SAM session and run the full HELLO/SESSION CREATE/NAMING/STREAM
        //    CONNECT exchange against the fuzz-controlled proxy. Dials are
        //    fire-and-forget (the RPC returns before the net thread runs the
        //    exchange); ordering no longer matters because connection k
        //    deterministically claims lane k.
        for k in 0..n_lanes {
            let _ = self.node.node.client.call::<serde_json::Value>(
                "addnode",
                &[dial_addr(k).into(), "onetry".into()],
            );
        }

        // 3. Wait for every proxy connection to finish serving its lane,
        //    instead of sleeping. Each handler sends exactly one `()` when it
        //    returns (script exhausted / promote socket closed / node hung
        //    up). A bounded backstop avoids an indefinite wait if the node
        //    decides not to dial at all for some lane (e.g. address parsing
        //    rejected it) — that just means fewer connections than lanes.
        //
        //    NOTE: "proxy finished serving" precedes "node finished reacting
        //    to the final reply" by a small, unbounded amount (the node still
        //    runs its catch/Disconnect/CheckControlSock path). For a
        //    crash/assert fuzzer this is fine: a fatal bug is still fatal a
        //    moment later when is_alive runs, and Nyx hang-detection covers
        //    infinite loops. There is no Bitcoin Core RPC/marker that blocks
        //    on "I2P net thread is idle", so a bounded backstop is the
        //    correct tool for the residual race, not a fixed sleep.
        let backstop = Duration::from_secs(20);
        for _ in 0..n_lanes {
            // recv_timeout returns Err on timeout *or* if all senders dropped
            // (every connection finished and the Session Arc went away). Both
            // mean "stop waiting".
            if done_rx.recv_timeout(backstop).is_err() {
                break;
            }
        }

        // 4. Detach the session so its sender(s) can drop and a late proxy
        //    connection from this case can't bleed into the next reset.
        if let Ok(mut g) = self.slot.lock() {
            *g = None;
        }

        if let Err(e) = self.node.is_alive() {
            return ScenarioResult::Fail(format!("Target is not alive: {e}"));
        }
        ScenarioResult::Ok
    }
}

fuzzamoto_main!(I2PSamScenario, TestCase);
