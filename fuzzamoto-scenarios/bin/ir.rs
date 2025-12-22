#[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
use std::time::{Duration, Instant};

use fuzzamoto::runners::Runner;

#[cfg(feature = "nyx")]
use fuzzamoto_nyx_sys::*;

use bitcoin::hashes::Hash;
use fuzzamoto::{
    connections::Transport,
    fuzzamoto_main,
    oracles::{CrashOracle, Oracle, OracleResult},
    scenarios::{Scenario, ScenarioInput, ScenarioResult, generic::GenericScenario},
    targets::{BitcoinCoreTarget, ConnectableTarget, HasTipHash, Target},
};

#[cfg(feature = "oracle_netsplit")]
use fuzzamoto::oracles::{NetSplitContext, NetSplitOracle};

#[cfg(feature = "oracle_consensus")]
use fuzzamoto::oracles::{ConsensusContext, ConsensusOracle};

use fuzzamoto_ir::{
    Program, ProgramContext,
    compiler::{CompiledAction, CompiledProgram, Compiler},
};

const COINBASE_MATURITY_HEIGHT_LIMIT: u32 = 100;
const LATE_BLOCK_HEIGHT_LIMIT: u32 = 190;
const COINBASE_VALUE: u64 = 25 * 100_000_000;
// OP_TRUE script pubkey: 0x0 0x20 sha256(OP_TRUE)
const OP_TRUE_SCRIPT_PUBKEY: [u8; 34] = [
    0u8, 32, 74, 232, 21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131,
    225, 85, 30, 111, 114, 30, 233, 192, 11, 140, 195, 50, 96,
];

/// `IrScenario` is a scenario with the same context as `GenericScenario` but it operates on
/// `fuzzamoto_ir::CompiledProgram`s as input.
struct IrScenario<TX: Transport, T: Target<TX> + ConnectableTarget> {
    inner: GenericScenario<TX, T>,
    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    second: T,
}

pub struct TestCase {
    program: CompiledProgram,
}

impl<'a> ScenarioInput<'a> for TestCase {
    fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        let program = if cfg!(feature = "compile_in_vm") {
            let program: Program = postcard::from_bytes(bytes).map_err(|e| e.to_string())?;
            let mut compiler = Compiler::new();
            compiler.compile(&program).map_err(|e| e.to_string())?
        } else {
            postcard::from_bytes(bytes).map_err(|e| e.to_string())?
        };
        Ok(Self { program })
    }
}

impl<TX, T> IrScenario<TX, T>
where
    TX: Transport,
    T: Target<TX> + HasTipHash + ConnectableTarget,
{
    /// Build the IR program context
    fn build_program_context(inner: &GenericScenario<TX, T>) -> ProgramContext {
        ProgramContext {
            num_nodes: 1,
            num_connections: inner.connections.len(),
            timestamp: inner.time,
        }
    }

    /// Extract coinbase outputs from mature blocks (height < 100) for use in IR programs
    fn build_txos(inner: &GenericScenario<TX, T>) -> Vec<fuzzamoto_ir::Txo> {
        let mut txos = Vec::new();
        for (block, _height) in inner
            .block_tree
            .values()
            .filter(|(_, height)| *height < COINBASE_MATURITY_HEIGHT_LIMIT)
        {
            let coinbase = block.coinbase().unwrap();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(
                coinbase
                    .compute_txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .as_slice(),
            );

            txos.push(fuzzamoto_ir::Txo {
                outpoint: (hash, 0u32),
                value: COINBASE_VALUE,
                script_pubkey: OP_TRUE_SCRIPT_PUBKEY.to_vec(),
                spending_script_sig: vec![],
                spending_witness: vec![vec![0x51]],
            });
        }
        txos
    }

    /// Extract block headers from late blocks (height > 190) for use in IR programs
    fn build_headers(inner: &GenericScenario<TX, T>) -> Vec<fuzzamoto_ir::Header> {
        inner
            .block_tree
            .values()
            .filter(|(_, height)| *height > LATE_BLOCK_HEIGHT_LIMIT)
            .map(|(block, height)| fuzzamoto_ir::Header {
                prev: *block.header.prev_blockhash.as_byte_array(),
                merkle_root: *block.header.merkle_root.as_byte_array(),
                nonce: block.header.nonce,
                bits: block.header.bits.to_consensus(),
                time: block.header.time,
                version: block.header.version.to_consensus(),
                height: *height,
            })
            .collect()
    }

    /// Dump the full program context either to Nyx host or to a file
    fn dump_context(
        context: ProgramContext,
        txos: Vec<fuzzamoto_ir::Txo>,
        headers: Vec<fuzzamoto_ir::Header>,
    ) -> Result<(), String> {
        let full_context = postcard::to_allocvec(&fuzzamoto_ir::FullProgramContext {
            context,
            txos,
            headers,
        })
        .map_err(|e| e.to_string())?;

        #[cfg(feature = "nyx")]
        {
            const CONTEXT_FILE_NAME: &str = "ir.context";
            unsafe {
                nyx_dump_file_to_host(
                    CONTEXT_FILE_NAME.as_ptr() as *const i8,
                    CONTEXT_FILE_NAME.len(),
                    full_context.as_ptr(),
                    full_context.len(),
                );
            }
        }

        #[cfg(not(feature = "nyx"))]
        if let Ok(context_file) = std::env::var("DUMP_CONTEXT") {
            std::fs::write(context_file, &full_context).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    fn create_and_sync_second_target(args: &[String], primary: &T) -> Result<T, String> {
        let mut second = if args.len() > 2 {
            T::from_path(&args[2])?
        } else {
            T::from_path(&args[1])?
        };
        second.connect_to(primary)?;
        Self::sync_nodes(primary, &mut second)?;
        Ok(second)
    }

    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
    fn sync_nodes(primary: &T, reference: &mut T) -> Result<(), String> {
        const SYNC_TIMEOUT: Duration = Duration::from_secs(10);
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let start = Instant::now();
        let mut synced = false;

        while start.elapsed() < SYNC_TIMEOUT {
            let primary_tip = primary.get_tip_hash();
            let reference_tip = reference.get_tip_hash();

            if primary_tip.is_some() && primary_tip == reference_tip {
                log::info!("Nodes synced successfully!");
                synced = true;
                break;
            }

            std::thread::sleep(POLL_INTERVAL);
        }

        if !synced {
            return Err("nodes failed to sync".to_string());
        }

        Ok(())
    }

    fn process_actions(
        &mut self,
        actions: Vec<CompiledAction>,
        start_index: usize,
        runner: &dyn Runner,
    ) -> Option<(Vec<u8>, usize)> {
        for (i, action) in actions.into_iter().enumerate().skip(start_index) {
            match action {
                CompiledAction::SendRawMessage(from, command, message) => {
                    if self.inner.connections.is_empty() {
                        return None;
                    }

                    let num_connections = self.inner.connections.len();
                    if let Some(connection) = self.inner.connections.get_mut(from % num_connections)
                    {
                        if cfg!(feature = "force_send_and_ping") {
                            let _ = connection.send_and_ping(&(command, message));
                        } else {
                            let _ = connection.send(&(command, message));
                        }
                    }
                }
                CompiledAction::SetTime(time) => {
                    let _ = self.inner.target.set_mocktime(time);
                    #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
                    let _ = self.second.set_mocktime(time);
                }
                CompiledAction::IncrementalSnapshot => {
                    // If we're creating a new temporary snapshot, we want to save the index to skip
                    // ahead to.
                    // TODO: Because we return if we're creating for the first time, this is slightly
                    //       wrong.
                    let prefix_index = i + 1;
                    let (new_payload, action_pos) = runner.create_tmp_and_next(prefix_index);
                    return Some((new_payload, action_pos));
                }
                _ => {}
            }
        }
        None
    }

    fn ping_connections(&mut self) {
        for connection in self.inner.connections.iter_mut() {
            let _ = connection.ping();
        }
    }

    fn evaluate_oracles(&mut self) -> ScenarioResult {
        let crash_oracle = CrashOracle::<TX>::default();
        if let OracleResult::Fail(e) = crash_oracle.evaluate(&self.inner.target) {
            return ScenarioResult::Fail(e.to_string());
        }

        #[cfg(feature = "oracle_netsplit")]
        {
            let net_split_oracle = NetSplitOracle::<TX, TX>::default();
            if let OracleResult::Fail(e) = net_split_oracle.evaluate(&NetSplitContext {
                primary: &self.inner.target,
                reference: &self.second,
            }) {
                return ScenarioResult::Fail(format!("{}", e));
            }
        }

        #[cfg(feature = "oracle_consensus")]
        {
            // Ensure the nodes are connected and eventually consistent (i.e. reach consensus
            // on the chain tip).
            if !self.second.is_connected_to(&self.inner.target) {
                let _ = self.second.connect_to(&self.inner.target);
            }

            let consensus_oracle = ConsensusOracle::<TX, TX>::default();
            if let OracleResult::Fail(e) = consensus_oracle.evaluate(&ConsensusContext {
                primary: &self.inner.target,
                reference: &self.second,
                // Poll every 10 milliseconds and timeout after 60 seconds. This way hang detection
                // will fĺag consensus bugs as hangs.
                consensus_timeout: Duration::from_secs(60),
                poll_interval: Duration::from_millis(10),
            }) {
                return ScenarioResult::Fail(format!("{}", e));
            }
        }

        ScenarioResult::Ok
    }
}

impl<TX, T> Scenario<'_, TestCase> for IrScenario<TX, T>
where
    TX: Transport,
    T: Target<TX> + HasTipHash + ConnectableTarget,
{
    fn new(args: &[String]) -> Result<Self, String> {
        let inner: GenericScenario<TX, T> = GenericScenario::new(args)?;

        let context = Self::build_program_context(&inner);
        log::info!("IR context: {:?}", context);

        let txos = Self::build_txos(&inner);
        let headers = Self::build_headers(&inner);

        Self::dump_context(context, txos, headers)?;

        #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
        let second = Self::create_and_sync_second_target(args, &inner.target)?;

        Ok(Self {
            inner,
            #[cfg(any(feature = "oracle_netsplit", feature = "oracle_consensus"))]
            second,
        })
    }

    fn run(&mut self, testcase: TestCase, runner: &dyn Runner) -> ScenarioResult {
        let mut actions = testcase.program.actions;
        let mut start_index = 0;

        loop {
            match self.process_actions(actions, start_index, runner) {
                Some((new_payload, action_pos)) => {
                    let new_testcase = match TestCase::decode(&new_payload) {
                        Ok(tc) => tc,
                        Err(e) => {
                            log::warn!("Failed to decode new payload after TMP: {}", e);
                            runner.skip();
                            return ScenarioResult::Skip;
                        }
                    };

                    // Resume just after the snapshot prefix.
                    actions = new_testcase.program.actions;
                    start_index = action_pos;

                    if start_index > actions.len() {
                        log::warn!(
                            "Action position {} exceeds action count {}, clamping",
                            start_index,
                            actions.len()
                        );
                        start_index = actions.len();
                    }
                }
                None => {
                    break;
                }
            }
        }
        self.ping_connections();
        self.evaluate_oracles()
    }
}

fuzzamoto_main!(
    IrScenario::<fuzzamoto::connections::V1Transport, BitcoinCoreTarget>,
    TestCase
);
