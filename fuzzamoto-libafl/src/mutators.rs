use std::borrow::Cow;

use fuzzamoto_ir::Program;

use libafl::{
    Error,
    common::HasMetadata,
    corpus::{Corpus, CorpusId, NopCorpus},
    inputs::BytesInput,
    mutators::{HavocScheduledMutator, MutationResult, Mutator, havoc_mutations},
    random_corpus_id,
    state::{HasCorpus, HasRand, StdState},
};
use libafl_bolts::{
    HasLen, Named,
    rands::{Rand, StdRand},
};
use rand::RngCore;

use crate::{input::IrInput, stages::RuntimeMetadata};

/// Instruction limit for mutated IR programs
const MAX_INSTRUCTIONS: usize = 40960;

pub struct IrMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

pub fn runtime_metadata_mut<S>(state: &mut S) -> &mut RuntimeMetadata
where
    S: HasMetadata,
{
    (state
        .metadata_mut::<RuntimeMetadata>()
        .expect("RuntimeMetadata should always exist at this point")) as _
}

impl<S, M, R> Mutator<IrInput, S> for IrMutator<M, R>
where
    S: HasRand + HasMetadata + HasCorpus<IrInput>,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let current_id = *state.corpus().current();

        let rt_data = runtime_metadata_mut(state);
        let is_first = rt_data.mutation_idx() == 0;
        rt_data.increment_idx();

        let tc_data = if is_first
            && let Some(id) = current_id
            && let Some(meta) = rt_data.metadata_mut(id)
        {
            Some(meta)
        } else {
            None
        };

        Ok(
            match self
                .mutator
                .mutate(input.ir_mut(), &mut self.rng, tc_data.as_deref())
            {
                Ok(()) => MutationResult::Mutated,
                _ => MutationResult::Skipped,
            },
        )
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrSpliceMutator<M, R> {
    mutator: M,
    rng: R,
    name: Cow<'static, str>,
}

impl<M, R> IrSpliceMutator<M, R>
where
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    pub fn new(mutator: M, rng: R) -> Self {
        let name = mutator.name();
        Self {
            mutator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, M, R> Mutator<IrInput, S> for IrSpliceMutator<M, R>
where
    S: HasRand + HasCorpus<IrInput> + HasMetadata,
    R: RngCore,
    M: fuzzamoto_ir::Mutator<R> + fuzzamoto_ir::Splicer<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let id = random_corpus_id!(state.corpus(), state.rand_mut());

        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current()
            && id == *cur
        {
            return Ok(MutationResult::Skipped);
        }

        let rt_data = runtime_metadata_mut(state);
        rt_data.increment_idx();

        let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        if other_testcase.scheduled_count() == 0 {
            // Don't splice with non-minimized inputs
            return Ok(MutationResult::Skipped);
        }

        let other = other_testcase.load_input(state.corpus())?;

        let mut input_clone = input.clone();
        if self
            .mutator
            .splice(input_clone.ir_mut(), other.ir(), &mut self.rng)
            .is_err()
        {
            return Ok(MutationResult::Skipped);
        }

        if input_clone.len() > MAX_INSTRUCTIONS {
            return Ok(MutationResult::Skipped);
        }

        *input = input_clone;

        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrSpliceMutator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct IrGenerator<G, R> {
    generator: G,
    rng: R,
    name: Cow<'static, str>,
}

impl<G, R> IrGenerator<G, R>
where
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    pub fn new(generator: G, rng: R) -> Self {
        let name = generator.name();
        Self {
            generator,
            rng,
            name: Cow::from(name),
        }
    }
}

impl<S, G, R> Mutator<IrInput, S> for IrGenerator<G, R>
where
    S: HasRand + HasMetadata + HasCorpus<IrInput>,
    R: RngCore,
    G: fuzzamoto_ir::Generator<R>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        let current_id = *state.corpus().current();

        let rt_data = runtime_metadata_mut(state);
        let is_first = rt_data.mutation_idx() == 0;
        rt_data.increment_idx();

        // Gate: generators that require metadata (transaction producers) only run as the first
        // sub-mutation of a scheduled stack. On later sub-mutations a prior mutation may have
        // reordered or spent the outputs they depend on, so skip them.
        if self.generator.requires_metadata() && !is_first {
            log::debug!(
                "[gate-dbg] IrGenerator '{}': GATED (requires_metadata, is_first=false) -> Skipped",
                self.generator.name()
            );
            return Ok(MutationResult::Skipped);
        }

        let mut tc_data = if is_first
            && let Some(id) = current_id
            && let Some(meta) = rt_data.metadata_mut(id)
        {
            Some(meta)
        } else {
            None
        };
        log::debug!(
            "[gate-dbg] IrGenerator '{}': is_first={} requires_meta={} tc_data_present={}",
            self.generator.name(),
            is_first,
            self.generator.requires_metadata(),
            tc_data.is_some()
        );

        let Some(index) =
            self.generator
                .choose_index(input.ir(), &mut self.rng, tc_data.as_deref_mut())
        else {
            log::debug!(
                "[gate-dbg] IrGenerator '{}': choose_index=None -> Skipped",
                self.generator.name()
            );
            return Ok(MutationResult::Skipped);
        };

        let mut builder = fuzzamoto_ir::ProgramBuilder::new(input.ir().context.clone());

        builder
            .append_all(input.ir().instructions[..index].iter().cloned())
            .expect("Partial append should always succeed if full append succeeded");

        let prev_var_count = builder.variable_count();

        if self
            .generator
            .generate(&mut builder, &mut self.rng, tc_data.as_deref())
            .is_err()
        {
            log::debug!(
                "[gate-dbg] IrGenerator '{}': generate() Err -> Skipped",
                self.generator.name()
            );
            return Ok(MutationResult::Skipped);
        }

        let second_half = Program::unchecked_new(
            input.ir().context.clone(),
            input.ir().instructions[index..].to_vec(),
        );
        let Ok(()) = builder.append_program(
            second_half,
            prev_var_count,
            builder.variable_count() - prev_var_count,
        ) else {
            log::warn!(
                "[gate-dbg] IrGenerator '{}': append_program failed -> Skipped",
                self.generator.name()
            );
            return Ok(MutationResult::Skipped);
        };

        let Ok(new_program) = builder.finalize() else {
            log::debug!(
                "[gate-dbg] IrGenerator '{}': finalize() Err -> Skipped",
                self.generator.name()
            );
            return Ok(MutationResult::Skipped);
        };

        if new_program.instructions.len() > MAX_INSTRUCTIONS {
            log::debug!(
                "[gate-dbg] IrGenerator '{}': program too large ({} instrs) -> Skipped",
                self.generator.name(),
                new_program.instructions.len()
            );
            return Ok(MutationResult::Skipped);
        }

        *input.ir_mut() = new_program;

        log::debug!(
            "[gate-dbg] IrGenerator '{}': Mutated OK",
            self.generator.name()
        );
        Ok(MutationResult::Mutated)
    }

    #[inline]
    fn post_exec(&mut self, state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        let rt_data = runtime_metadata_mut(state);
        rt_data.reset_idx();

        Ok(())
    }
}

impl<M, R> Named for IrGenerator<M, R> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub struct LibAflByteMutator {
    state: StdState<NopCorpus<BytesInput>, BytesInput, StdRand, NopCorpus<BytesInput>>,
}

impl LibAflByteMutator {
    pub fn new() -> Self {
        let state = StdState::new(
            StdRand::new(),
            NopCorpus::<BytesInput>::new(),
            NopCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        Self { state }
    }
}

impl fuzzamoto_ir::OperationByteMutator for LibAflByteMutator {
    fn mutate_bytes(&mut self, bytes: &mut Vec<u8>) {
        let mut input = BytesInput::from(bytes.clone());

        let mut mutator = HavocScheduledMutator::new(havoc_mutations());
        let _ = mutator.mutate(&mut self.state, &mut input);

        bytes.clear();
        bytes.extend(input.into_inner());
    }
}

/// Wrapper around the top-level scheduled mutator that resets the per-stack sub-mutation counter
/// at the start of every `mutate` call.
///
/// The mutational stage invokes the top-level mutator's `mutate` exactly once per input (that call
/// expands into one scheduled *stack* of sub-mutations), and only calls `post_exec` when the stack
/// did not return `Skipped`. The sub-mutators' `is_first` flag is derived from `RuntimeMetadata`'s
/// `mutation_idx`, which is reset in `post_exec` — so on an all-skipped stack the counter is never
/// reset and would climb forever, permanently wedging the `is_first` gate (all transaction
/// generators would be skipped, freezing coverage growth). Resetting here — at the guaranteed
/// once-per-stack boundary — makes `is_first` correct regardless of whether `post_exec` runs.
#[derive(Debug)]
pub struct StackResetMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M> StackResetMutator<M> {
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            name: Cow::Borrowed("StackResetMutator"),
        }
    }
}

impl<M> Named for StackResetMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S, M> Mutator<IrInput, S> for StackResetMutator<M>
where
    S: HasMetadata,
    M: Mutator<IrInput, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut IrInput) -> Result<MutationResult, Error> {
        // Start of a new scheduled stack: position 0.
        runtime_metadata_mut(state).reset_idx();
        self.inner.mutate(state, input)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}
