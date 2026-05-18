//! I2P SAM control-protocol fuzzing scenario for Bitcoin Core.
//!
//! Fuzzes the **SAM proxy protocol parser** in `i2p.cpp`: reply tokenizing
//! (`SendRequestAndGetReply`, `Reply::Get`, `Split`), `SwapBase64` /
//! `DecodeI2PBase64`, `DestBinToAddr` -> `CNetAddr::SetSpecial`,
//! `MyDestination` certificate-length parsing, and the `SESSION CREATE` /
//! `NAMING LOOKUP` / `STREAM CONNECT` / `STREAM ACCEPT` result handling
//! including their `INVALID_ID` / `CANT_REACH_PEER` / `TIMEOUT` /
//! `RESULT=I2P_ERROR` branches and the `CheckControlSock` / `Disconnect`
//! teardown paths. The fuzz input controls every byte the fake in-process
//! SAM proxy sends back.
//!
//! ## Two modes (compile-time)
//!
//! * **Outbound (default).** `-i2pacceptincoming=0`, so `net.cpp` builds no
//!   persistent session and there is *no* SAM traffic before the snapshot.
//!   Each post-snapshot `addnode <i2p> onetry` builds a fresh **transient**
//!   session whose full `HELLO` / `SESSION CREATE` (transient `DESTINATION=`)
//!   / `NAMING LOOKUP` / `STREAM CONNECT` exchange is fuzzed.
//!
//! * **Inbound** (`--features i2p_inbound`). `-i2pacceptincoming=1`, so
//!   `ThreadI2PAcceptIncoming` runs: `Listen()` ->
//!   `CreateIfNotCreatedAlready()` (persistent: `HELLO`, possibly
//!   `DEST GENERATE`, `SESSION CREATE`) once at startup, then a continuous
//!   loop of `StreamAccept()` (`HELLO` + `STREAM ACCEPT` on a fresh socket)
//!   followed by `Accept()` reading a peer destination line. The startup
//!   handshake happens *before* the snapshot, so the proxy answers it with
//!   **canned valid** replies (deterministic); every post-snapshot
//!   `STREAM ACCEPT` round and the peer-destination line `Accept()` reads
//!   are **fuzzed**. This is the more security-relevant surface: those bytes
//!   originate from an untrusted remote peer relayed by the router.
//!
//! ## Adversarial framing (#2)
//!
//! Each fuzzed reply also carries fuzz-controlled *delivery* options, so the
//! proxy can behave like a hostile router, not just send a clean line:
//!   * split the blob into many small TCP writes,
//!   * omit the trailing `\n` terminator entirely (exercises the
//!     `RecvUntilTerminator` `MAX_MSG_SIZE` runaway-guard / timeout that
//!     `i2p.h` documents as defending against a malicious proxy),
//!   * close the socket mid-reply.
//! A hard wall-clock guard keeps throughput sane despite the no-terminator
//! case (`i2p.cpp`'s real control timeout is 3 minutes; we never wait that
//! long — see `NO_TERM_LINGER`).
//!
//! ## Snapshot model
//!
//! The fuzzamoto snapshot is taken in `runner.get_fuzz_input()`, after
//! `Scenario::new` returns. Outbound mode has zero pre-snapshot SAM traffic.
//! Inbound mode's only pre-snapshot SAM traffic is the one deterministic
//! persistent-session handshake, answered with fixed valid bytes. Either
//! way each reset replays from an identical post-setup state and the fuzz
//! input drives only post-snapshot SAM bytes. Liveness is checked with
//! `is_alive`; a crash/assert/hang in the I2P path fails the case.

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
    time::{Duration, Instant},
};

/// SAM 3.1 fixed virtual port. `i2p.cpp::Session::Connect` refuses any other.
/// Only used to build the dialed address in outbound mode; in inbound mode
/// no address is dialed, so gate it the same way as `dial_addr` to avoid a
/// dead-code error under `-D warnings`.
#[cfg(not(feature = "i2p_inbound"))]
const I2P_SAM31_PORT: u16 = 0;

/// Hard cap on one fuzz-controlled reply blob, well below the 64 KiB
/// `MAX_MSG_SIZE` so the *terminated* case never approaches the runaway
/// guard; the no-terminator case is bounded by time instead (below).
const MAX_REPLY_BLOB: usize = 4096;

/// Max SAM requests answered per control socket (defensive against the node
/// looping on one socket and exhausting the lane).
const MAX_REQUESTS_PER_CONN: usize = 16;

/// When a reply deliberately omits its `\n` terminator, the node will block
/// in `RecvUntilTerminator` until its own timeout (3 min control / shorter
/// for accept). We must not wait that long, so after sending the
/// unterminated bytes we linger only briefly, then close the socket. Closing
/// makes `RecvUntilTerminator` observe EOF and raise promptly — exercising
/// the same error path far faster.
const NO_TERM_LINGER: Duration = Duration::from_millis(150);

/// Backstop for the per-case completion wait (see `run`). Real proxy
/// connections arrive within tens of ms or not at all.
const COMPLETION_BACKSTOP: Duration = Duration::from_secs(5);

// --------------------------------------------------------------------------
// Fuzz input
// --------------------------------------------------------------------------

/// How the proxy *delivers* a reply blob (adversarial framing, #2).
#[derive(Clone, Copy, PartialEq)]
enum Framing {
    /// Send blob, then exactly one `\n` (well-formed proxy).
    Clean,
    /// Send blob in 1-byte TCP writes, then one `\n` (fragmented).
    Chunked,
    /// Send blob with NO terminator, linger `NO_TERM_LINGER`, then close
    /// (forces the node's recv timeout / EOF error path).
    NoTerminator,
    /// Send blob (+`\n`), then immediately close the socket (mid-exchange
    /// teardown; exercises `CheckControlSock`/`Disconnect`).
    CloseAfter,
}

impl Framing {
    fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0 => Framing::Clean,
            1 => Framing::Chunked,
            2 => Framing::NoTerminator,
            _ => Framing::CloseAfter,
        }
    }
}

/// One scripted reply: raw bytes + delivery framing + the `promote` bit
/// (after a successful `STREAM CONNECT`/`STREAM ACCEPT` the node treats the
/// socket as a raw P2P stream; we then just drain so net.cpp's post-connect
/// plumbing is also reached).
#[derive(Clone)]
struct Reply {
    blob: Vec<u8>,
    framing: Framing,
    promote: bool,
}

struct TestCase {
    /// One lane per SAM control connection the node opens. Outbound mode:
    /// lane = one transient dial's reply sequence. Inbound mode: lane = one
    /// `StreamAccept`/`Accept` round's replies (request 0 -> HELLO reply,
    /// 1 -> STREAM ACCEPT reply, 2 -> the peer-destination line read by
    /// `Session::Accept`).
    lanes: Vec<Vec<Reply>>,
}

impl<'a> ScenarioInput<'a> for TestCase {
    /// Tolerant, length-prefixed wire format (truncation never errors — the
    /// decoder stops early so the mutator can splice freely):
    ///
    /// ```text
    ///   u8        first_byte   -> n_lanes = (first_byte % 64) + 1   (1..=64)
    ///   n_lanes x {
    ///     u8      n_replies    -> min(b, 8)
    ///     n_replies x {
    ///       u8     flags       (bit0 = promote; bits1..2 = Framing)
    ///       u16 le blob_len    (clamped to MAX_REPLY_BLOB and to remaining)
    ///       blob_len blob
    ///     }
    ///   }
    /// ```
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let mut pos = 0usize;

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
                    framing: Framing::from_bits(flags >> 1),
                    promote: flags & 1 != 0,
                });
            }
            lanes.push(lane);
        }

        Ok(TestCase { lanes })
    }
}

// --------------------------------------------------------------------------
// Fake SAM proxy
// --------------------------------------------------------------------------

/// A structurally valid I2P private key / destination blob: exactly 387
/// bytes with a zero certificate length at bytes 385..387 (big-endian), so
/// `i2p.cpp::Session::MyDestination` accepts it (dest_len = 387 <= 387). Used
/// only for the deterministic, pre-snapshot persistent-session handshake in
/// inbound mode; never fuzzed.
fn canned_priv_key() -> Vec<u8> {
    let mut k = vec![0u8; 387];
    // Arbitrary fixed, deterministic content; the exact bytes don't matter,
    // only the length and the zero cert-length field.
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    k[385] = 0;
    k[386] = 0;
    k
}

const STD_B64: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_std(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(STD_B64[((n >> 18) & 63) as usize] as char);
        out.push(STD_B64[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            STD_B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            STD_B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// I2P-flavoured Base64 (`+`->`-`, `/`->`~`) of the canned key, as
/// `DEST GENERATE` / `SESSION CREATE` would return it.
fn canned_dest_i2p_b64() -> String {
    base64_std(&canned_priv_key())
        .chars()
        .map(|ch| match ch {
            '+' => '-',
            '/' => '~',
            x => x,
        })
        .collect()
}

/// Per-connection completion signalling + lane handout.
struct Session {
    lanes: Vec<Vec<Reply>>,
    conn_counter: AtomicUsize,
    done_tx: mpsc::Sender<()>,
}

impl Session {
    fn claim_lane(&self) -> Vec<Reply> {
        let k = self.conn_counter.fetch_add(1, Ordering::SeqCst);
        self.lanes.get(k).cloned().unwrap_or_default()
    }
}

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
                    // No session installed yet => pre-snapshot. In inbound
                    // mode that is the persistent handshake: answer it with
                    // canned-valid replies and DO NOT signal completion (it
                    // is not a fuzzed lane). In outbound mode there is no
                    // pre-snapshot traffic, so this branch is just defensive.
                    let session = slot.lock().ok().and_then(|g| g.clone());
                    match session {
                        None => {
                            let _ = handle_canned_conn(stream);
                        }
                        Some(session) => {
                            let lane = session.claim_lane();
                            let _ = handle_fuzzed_conn(stream, lane);
                            let _ = session.done_tx.send(());
                        }
                    }
                });
            }
        })
        .map_err(|e| format!("spawn fuzzed SAM thread: {e}"))?;

    Ok(addr)
}

/// Peek the SAM verb of a request line without consuming/parsing semantics.
/// We only need to distinguish a few first words to answer the *pre-snapshot*
/// persistent handshake correctly.
fn sam_verb(line: &[u8]) -> &'static str {
    let s = line;
    let starts = |p: &[u8]| s.len() >= p.len() && &s[..p.len()] == p;
    if starts(b"HELLO") {
        "HELLO"
    } else if starts(b"DEST GENERATE") {
        "DEST"
    } else if starts(b"SESSION CREATE") {
        "SESSION"
    } else if starts(b"STREAM ACCEPT") {
        "STREAM_ACCEPT"
    } else if starts(b"STREAM CONNECT") {
        "STREAM_CONNECT"
    } else if starts(b"NAMING LOOKUP") {
        "NAMING"
    } else {
        "OTHER"
    }
}

/// Pre-snapshot, non-fuzzed connection: answer the persistent-session
/// handshake (`HELLO`, optional `DEST GENERATE`, `SESSION CREATE`) and any
/// `STREAM ACCEPT` with deterministically valid SAM so the node finishes
/// startup. Only reached in inbound mode before the fuzz session is
/// installed.
fn handle_canned_conn(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = stream.try_clone()?;
    let mut writer = stream;
    let mut buf = [0u8; 1024];
    let mut line: Vec<u8> = Vec::new();
    let dest = canned_dest_i2p_b64();

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        line.extend_from_slice(&buf[..n]);
        while let Some(p) = line.iter().position(|&b| b == b'\n') {
            let req: Vec<u8> = line.drain(..=p).collect();
            let reply: String = match sam_verb(&req) {
                "HELLO" => "HELLO REPLY RESULT=OK VERSION=3.1\n".into(),
                "DEST" => format!("DEST REPLY PUB={dest} PRIV={dest}\n"),
                "SESSION" => {
                    format!("SESSION STATUS RESULT=OK DESTINATION={dest}\n")
                }
                "STREAM_ACCEPT" => "STREAM STATUS RESULT=OK\n".into(),
                "NAMING" => {
                    format!("NAMING REPLY RESULT=OK NAME=ME VALUE={dest}\n")
                }
                "STREAM_CONNECT" => "STREAM STATUS RESULT=OK\n".into(),
                _ => "RESULT=OK\n".into(),
            };
            if writer.write_all(reply.as_bytes()).is_err()
                || writer.flush().is_err()
            {
                return Ok(());
            }
        }
    }
}

/// Post-snapshot, fuzzed connection: each SAM request gets the next lane
/// reply, delivered with its fuzz-chosen framing.
fn handle_fuzzed_conn(stream: TcpStream, lane: Vec<Reply>) -> std::io::Result<()> {
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
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        line.extend_from_slice(&buf[..n]);

        while let Some(p) = line.iter().position(|&b| b == b'\n') {
            let _req: Vec<u8> = line.drain(..=p).collect();

            let reply = lane.get(served).cloned().unwrap_or(Reply {
                blob: Vec::new(),
                framing: Framing::Clean,
                promote: false,
            });
            served += 1;

            let blob: &[u8] = if reply.blob.len() > MAX_REPLY_BLOB {
                &reply.blob[..MAX_REPLY_BLOB]
            } else {
                &reply.blob
            };

            match reply.framing {
                Framing::Clean => {
                    if writer.write_all(blob).is_err()
                        || writer.write_all(b"\n").is_err()
                        || writer.flush().is_err()
                    {
                        return Ok(());
                    }
                }
                Framing::Chunked => {
                    let mut ok = true;
                    for byte in blob {
                        if writer.write_all(&[*byte]).is_err()
                            || writer.flush().is_err()
                        {
                            ok = false;
                            break;
                        }
                    }
                    if !ok
                        || writer.write_all(b"\n").is_err()
                        || writer.flush().is_err()
                    {
                        return Ok(());
                    }
                }
                Framing::NoTerminator => {
                    // Send the bytes WITHOUT a terminator, linger briefly so
                    // the node is genuinely blocked in RecvUntilTerminator,
                    // then close so it observes EOF and raises promptly
                    // (instead of waiting out i2p.cpp's multi-minute
                    // timeout). Same error path, bounded time.
                    let _ = writer.write_all(blob);
                    let _ = writer.flush();
                    thread::sleep(NO_TERM_LINGER);
                    return Ok(()); // drop => socket close => node sees EOF
                }
                Framing::CloseAfter => {
                    let _ = writer.write_all(blob);
                    let _ = writer.write_all(b"\n");
                    let _ = writer.flush();
                    return Ok(()); // immediate teardown
                }
            }

            if reply.promote {
                // Successful STREAM CONNECT/ACCEPT: node now treats the
                // socket as raw P2P. Drain & ignore; it will time the silent
                // peer out. Exercises net.cpp post-connect plumbing.
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
// Bitcoin Core node
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

        #[cfg(feature = "inherit_stdout")]
        {
            conf.args.extend_from_slice(&[
                "-debug",
                "-debugexclude=libevent",
                "-debugexclude=leveldb",
            ]);
            conf.view_stdout = true;
        }

        // Inbound mode enables ThreadI2PAcceptIncoming (the persistent
        // session + StreamAccept/Accept loop). Outbound mode disables it so
        // there is zero pre-snapshot SAM traffic.
        #[cfg(feature = "i2p_inbound")]
        let accept_arg = "-i2pacceptincoming=1";
        #[cfg(not(feature = "i2p_inbound"))]
        let accept_arg = "-i2pacceptincoming=0";

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
            i2psam.as_str(),
            accept_arg,
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
        let slot: SessionSlot = Arc::new(Mutex::new(None));
        let sam_addr = spawn_sam_proxy(Arc::clone(&slot))?;
        let node = I2PNode::start(exe_path, sam_addr)?;
        Ok(Self { node, slot })
    }
}

/// Distinct, syntactically valid 52-char base32 `.b32.i2p` address for dial
/// `k` (outbound mode only). Must be unique or `addnode` rejects the
/// duplicate. Index 51 stays `'a'` (base32 0) so the 4 padding bits are
/// zero -> canonical, parseable by `CNetAddr::SetSpecial`.
#[cfg(not(feature = "i2p_inbound"))]
fn dial_addr(k: usize) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut label = [b'a'; 52];
    let mut v = k;
    let mut i = 0;
    while v > 0 && i < label.len() {
        label[i] = A[v & 31];
        v >>= 5;
        i += 1;
    }
    let label = std::str::from_utf8(&label).unwrap_or("a");
    format!("{label}.b32.i2p:{I2P_SAM31_PORT}")
}

impl<'a> Scenario<'a, TestCase> for I2PSamScenario {
    fn new(args: &[String]) -> Result<Self, String> {
        Self::build(&args[1])
    }

    fn run(&mut self, testcase: TestCase) -> ScenarioResult {
        let n_lanes = testcase.lanes.len();

        let (done_tx, done_rx) = mpsc::channel::<()>();
        let session = Arc::new(Session {
            lanes: testcase.lanes,
            conn_counter: AtomicUsize::new(0),
            done_tx,
        });
        if let Ok(mut g) = self.slot.lock() {
            *g = Some(Arc::clone(&session));
        }

        // Inbound mode: ThreadI2PAcceptIncoming is already looping
        // StreamAccept/Accept on its own; installing the fuzz session above
        // is all that is needed — the next `StreamAccept` connections hit
        // `handle_fuzzed_conn`. We just wait for completions.
        //
        // Outbound mode: trigger one transient dial per lane.
        #[cfg(not(feature = "i2p_inbound"))]
        for k in 0..n_lanes {
            let _ = self.node.node.client.call::<serde_json::Value>(
                "addnode",
                &[dial_addr(k).into(), "onetry".into()],
            );
        }

        // Wait for proxy connections to finish serving their lanes instead
        // of sleeping. Each fuzzed connection signals once. Inbound mode's
        // accept loop is continuous, so we additionally bound the whole wait
        // by an overall deadline (a lane may also simply never be reached if
        // the node tears the session down early).
        let deadline = Instant::now() + COMPLETION_BACKSTOP;
        for _ in 0..n_lanes {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if done_rx.recv_timeout(deadline - now).is_err() {
                break; // timeout, or all senders dropped
            }
        }

        // Detach so late connections from this case can't bleed into the
        // next reset, and the sender(s) can drop.
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
