use std::marker::PhantomData;

use libafl::{
    Evaluator, HasMetadata,
    corpus::Corpus,
    executors::{Executor, HasObservers},
    observers::ObserversTuple,
    stages::{
        Restartable, Stage,
        mutational::{MutatedTransform, MutatedTransformPost},
    },
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::Error;
use rand::RngCore;

use fuzzamoto_ir::{Generator, PerTestcaseMetadata, Program, ProgramBuilder};

use crate::input::IrInput;
use crate::stages::probe::RuntimeMetadata;

/// Keep in sync with the limit enforced by the havoc mutators in `crate::mutators`.
const MAX_INSTRUCTIONS: usize = 4096;

/// A dedicated generation stage that drives txo-feedback-aware generators with the
/// per-testcase runtime metadata *guaranteed*, rather than letting them compete for
/// the first-mutation slot of the havoc scheduler.
///
/// The runtime txo metadata is only valid on the first mutation of a chain, because
/// it records absolute variable indices into the *pristine* corpus program. In the
/// havoc stage the metadata is therefore handed to whichever sub-mutation happens to
/// run first, and high-weight mutators (e.g. `InputMutator`) almost always win that
/// slot, so the feedback rarely reaches a transaction generator.
///
/// This stage removes the competition: for each scheduled testcase that has recorded
/// txo metadata, it applies the configured generators directly, always starting from
/// the pristine program (so the recorded indices stay valid) and always passing the
/// metadata through. Generated programs are evaluated normally, so interesting ones
/// enter the corpus.
pub struct TxoGenerateStage<R, E, S> {
    generators: Vec<Box<dyn Generator<R>>>,
    iters: usize,
    rng: R,
    phantom: PhantomData<(E, S)>,
}

impl<R, E, S> TxoGenerateStage<R, E, S>
where
    R: RngCore,
{
    /// Create a new stage applying `generators` (chosen uniformly at random) `iters`
    /// times per scheduled testcase that carries txo feedback.
    pub fn new(generators: Vec<Box<dyn Generator<R>>>, iters: usize, rng: R) -> Self {
        Self {
            generators,
            iters,
            rng,
            phantom: PhantomData,
        }
    }
}

/// Insert `generator`'s output into `input` with `meta` available, returning the new
/// program as an `IrInput`. Mirrors the program-building logic of
/// `crate::mutators::IrGenerator::mutate`, but the metadata is always supplied and the
/// source program is always the (pristine) `input`.
fn generate_with_meta<R: RngCore>(
    generator: &dyn Generator<R>,
    input: &IrInput,
    rng: &mut R,
    meta: Option<&PerTestcaseMetadata>,
) -> Option<IrInput> {
    let index = generator.choose_index(input.ir(), rng, meta)?;

    let mut builder = ProgramBuilder::new(input.ir().context.clone());
    builder
        .append_all(input.ir().instructions[..index].iter().cloned())
        .ok()?;

    let prev_var_count = builder.variable_count();
    generator.generate(&mut builder, rng, meta).ok()?;

    let second_half = Program::unchecked_new(
        input.ir().context.clone(),
        input.ir().instructions[index..].to_vec(),
    );
    builder
        .append_program(
            second_half,
            prev_var_count,
            builder.variable_count() - prev_var_count,
        )
        .ok()?;

    let new_program = builder.finalize().ok()?;
    if new_program.instructions.len() > MAX_INSTRUCTIONS {
        return None;
    }

    let mut new_input = input.clone();
    *new_input.ir_mut() = new_program;
    Some(new_input)
}

impl<R, E, EM, S, Z, OT> Stage<E, EM, S, Z> for TxoGenerateStage<R, E, S>
where
    R: RngCore,
    E: Executor<EM, IrInput, S, Z> + HasObservers<Observers = OT>,
    OT: ObserversTuple<IrInput, S>,
    Z: Evaluator<E, EM, IrInput, S>,
    S: HasMetadata + HasCorpus<IrInput> + HasCurrentTestcase<IrInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if self.generators.is_empty() {
            return Ok(());
        }

        let current = *state.corpus().current();
        let Some(cur) = current else {
            return Ok(());
        };

        // Pull the pristine input for this testcase.
        let mut testcase = state.current_testcase_mut()?.clone();
        let Ok(input) = IrInput::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };

        // Read (and clone out) the recorded metadata for this corpus entry. If there
        // is nothing recorded yet, or it carries no txo info, this stage can add
        // nothing over the regular generators, so skip.
        let meta = state
            .metadata_mut::<RuntimeMetadata>()
            .ok()
            .and_then(|rt| rt.metadata_mut(cur).map(|m| m.clone()));
        let Some(meta) = meta else {
            return Ok(());
        };
        let txo = meta.txo_metadata();
        if txo.used_txos.is_empty() && txo.created_txos.is_empty() {
            return Ok(());
        }

        for _ in 0..self.iters {
            // Always generate from the pristine program so the recorded indices in
            // `meta` remain valid (this is the same invariant the havoc `is_first`
            // gate relies on, made explicit here).
            let gen_index = (self.rng.next_u32() as usize) % self.generators.len();
            let Some(new_input) = generate_with_meta(
                self.generators[gen_index].as_ref(),
                &input,
                &mut self.rng,
                Some(&meta),
            ) else {
                continue;
            };

            let (untransformed, post) = new_input.try_transform_into(state)?;
            let _ = fuzzer.evaluate_input(state, executor, manager, &untransformed)?;
            post.post_exec(state, None)?;
        }

        Ok(())
    }
}

impl<R, E, S> Restartable<S> for TxoGenerateStage<R, E, S> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}
