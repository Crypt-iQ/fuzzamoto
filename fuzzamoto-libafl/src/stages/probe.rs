use crate::input::IrInput;
use fuzzamoto_ir::{Instruction, Operation};
use fuzzamoto_ir::{ProbeResult, ProbeResults};
use libafl::ExecutesInput;
use libafl::{
    HasMetadata,
    corpus::{Corpus, CorpusId},
    executors::{Executor, HasObservers},
    observers::{ObserversTuple, StdOutObserver},
    stages::{
        Restartable, Stage,
        mutational::{MutatedTransform, MutatedTransformPost},
    },
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::{impl_serdeany, tuples::Handle};
use std::collections::{HashMap, HashSet};

use base64::prelude::{BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};

pub struct ProbingStage<T> {
    seen: HashSet<CorpusId>,
    handle: Handle<T>,
}

impl<T> ProbingStage<T> {
    pub fn new(observer_handle: &Handle<T>) -> Self {
        Self {
            seen: HashSet::new(),
            handle: observer_handle.clone(),
        }
    }
}

/// Runtime metadata for fuzzamoto. This data is changed at runtime in response to the harness execution during fuzzing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    // TODO: If you want to add another metadata, then add it to `PerTestcaseMetadata` (not here!)
    metadatas: HashMap<CorpusId, fuzzamoto_ir::PerTestcaseMetadata>,
    mutation_idx: usize,
}

impl RuntimeMetadata {
    pub fn metadata_mut(&mut self, id: CorpusId) -> Option<&mut fuzzamoto_ir::PerTestcaseMetadata> {
        self.metadatas.get_mut(&id)
    }

    /// Number of probed mempool transactions recorded for a corpus entry (0 if none).
    pub fn mempool_tx_count(&self, id: CorpusId) -> Option<usize> {
        self.metadatas
            .get(&id)
            .map(|m| m.txo_metadata().txo_entry.len())
    }

    /// Drop stored metadata for a corpus entry that has been removed/replaced, so `metadatas`
    /// doesn't grow unboundedly as the corpus churns.
    pub fn remove_metadata(&mut self, id: CorpusId) {
        self.metadatas.remove(&id);
    }

    pub fn increment_idx(&mut self) {
        self.mutation_idx += 1;
    }

    pub fn reset_idx(&mut self) {
        self.mutation_idx = 0;
    }

    pub fn mutation_idx(&self) -> usize {
        self.mutation_idx
    }
}

impl_serdeany!(RuntimeMetadata);

/// Parse the incoming message from the other peer and process it
pub fn process_probe_results<S>(state: &mut S, results: &ProbeResults)
where
    S: HasMetadata + HasCorpus<IrInput>,
{
    for result in results {
        match result {
            ProbeResult::GetBlockTxn { get_block_txn } => {
                let current = *state.corpus().current();
                if let Some(cur) = current
                    && let Ok(meta) = state.metadata_mut::<RuntimeMetadata>()
                {
                    let txvec = meta.metadatas.entry(cur).or_default();
                    txvec.add_block_tx_request(get_block_txn.clone());
                }
            }
            ProbeResult::Mempool { txo_entry } => {
                let current = *state.corpus().current();
                if let Some(cur) = current {
                    if let Ok(meta) = state.metadata_mut::<RuntimeMetadata>() {
                        let txvec = meta.metadatas.entry(cur).or_default();
                        txvec.add_txo_entry(txo_entry.clone());
                    }
                    // Attach the mempool size to the testcase so the scheduler can favour
                    // corpus entries that produce larger mempools.
                    if let Ok(tc) = state.corpus().get(cur) {
                        tc.borrow_mut()
                            .add_metadata(MempoolSizeMetadata(txo_entry.len()));
                    }
                    log::info!(
                        "[gate-dbg] process_probe_results: stored {} mempool txos for corpus {cur:?}",
                        txo_entry.len()
                    );
                }
            }
            ProbeResult::Failure { command, reason } => {
                log::info!("Command {command:?} couln't be parsed; reason: {reason:?}");
            }
            ProbeResult::RecentBlockes { result } => {
                let current = *state.corpus().current();
                if let Some(cur) = current
                    && let Ok(meta) = state.metadata_mut::<RuntimeMetadata>()
                {
                    let txvec = meta.metadatas.entry(cur).or_default();
                    txvec.add_recent_blocks(result.clone());
                }
            }
        }
    }
}

impl<E, EM, OT, S, T, Z> Stage<E, EM, S, Z> for ProbingStage<T>
where
    E: Executor<EM, IrInput, S, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<IrInput, S>,
    Z: ExecutesInput<E, EM, IrInput, S>,
    T: AsRef<StdOutObserver>,
    S: HasMetadata + HasCorpus<IrInput> + HasCurrentTestcase<IrInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), libafl::Error> {
        if !state.has_metadata::<RuntimeMetadata>() {
            state.add_metadata(RuntimeMetadata::default());
        }

        let mut testcase = state.current_testcase_mut()?.clone();
        let Ok(input) = IrInput::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        let mut cloned_input = input.clone();
        let cur = state
            .corpus()
            .current()
            .expect("CorpusId should be available during stage execution");

        if self.seen.contains(&cur) {
            return Ok(());
        }

        // Prepend a `Probe` instruction to the program. Note: since `Probe` does not create any variables,
        // we don't have to care worry about adjusting variable indices here
        debug_assert_eq!(Operation::Probe.num_outputs(), 0);
        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());
        assert!(builder.instructions.is_empty());
        builder
            .append(Instruction {
                inputs: vec![],
                operation: Operation::Probe,
            })
            .expect("appending EnableProbe should always succeed");
        builder
            .append_all(input.ir().instructions.iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");
        let Ok(new_program) = builder.finalize() else {
            return Ok(());
        };

        // now swap it with the new program
        *cloned_input.ir_mut() = new_program;
        let (untransformed, post) = cloned_input.try_transform_into(state)?;
        log::info!(
            "Probing for testcase {:?} (in {:?})",
            cur,
            testcase.file_path()
        );
        let _exit_kind = fuzzer.execute_input(state, executor, manager, &untransformed)?;

        let observers = executor.observers();
        let stdout_observer = observers[&self.handle].as_ref();
        let buffer = stdout_observer
            .output
            .as_ref()
            .ok_or(libafl::Error::illegal_state("StdOutObserver has no stdout"))?;
        if !buffer.is_empty() {
            let stdout = String::from_utf8_lossy(buffer);
            for line in stdout.lines() {
                let trimmed = line.trim().trim_matches(|c| c == '\0');
                if trimmed.is_empty() {
                    continue;
                }

                if let Ok(fuzzamoto::StdoutMessage::Probe(data)) =
                    serde_json::from_str::<fuzzamoto::StdoutMessage>(trimmed)
                {
                    if let Ok(decoded) = BASE64_STANDARD.decode(&data)
                        && let Ok(results) = postcard::from_bytes::<ProbeResults>(&decoded)
                    {
                        process_probe_results(state, &results);
                    } else {
                        log::info!("Failed to decode probe data from the target!");
                    }
                }
            }
        }

        post.post_exec(state, None)?;
        log::info!("Done Probing for testcase {cur:?}");
        self.seen.insert(cur);
        Ok(())
    }
}

impl<S, T> Restartable<S> for ProbingStage<T> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, libafl::Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), libafl::Error> {
        Ok(())
    }
}

/// Testcase metadata recording how many mempool transactions this input produced (attached by the
/// probing stage). Used by `MempoolWeightTestcaseScore` to bias scheduling toward inputs that grow
/// the mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSizeMetadata(pub usize);

impl_serdeany!(MempoolSizeMetadata);

/// A `TestcaseScore` that starts from the standard corpus weight and multiplies it by a factor
/// that grows with the input's recorded mempool size, so larger-mempool inputs are scheduled more.
#[derive(Debug, Clone)]
pub struct MempoolWeightTestcaseScore;

impl<I, S> libafl::schedulers::testcase_score::TestcaseScore<I, S> for MempoolWeightTestcaseScore
where
    S: libafl::HasMetadata + libafl::state::HasCorpus<I>,
{
    fn compute(
        state: &S,
        entry: &mut libafl::corpus::Testcase<I>,
    ) -> Result<f64, libafl::Error> {
        let base = <libafl::schedulers::testcase_score::CorpusWeightTestcaseScore as libafl::schedulers::testcase_score::TestcaseScore<I, S>>::compute(state, entry)?;
        let mempool = entry
            .metadata::<MempoolSizeMetadata>()
            .map(|m| m.0)
            .unwrap_or(0);
        // Linear boost: each mempool tx adds 5% to the base weight. Tune as needed.
        let factor = 1.0 + 0.05 * (mempool as f64);
        Ok(base * factor)
    }
}
