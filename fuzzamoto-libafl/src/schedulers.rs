use std::marker::PhantomData;

use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    schedulers::{HasQueueCycles, RemovableScheduler, Scheduler},
    state::HasCorpus,
};
use libafl_bolts::tuples::MatchName;

pub enum SupportedSchedulers<Q, M> {
    Queue(Q, PhantomData<M>),
    LenTimeMinimizer(M, PhantomData<Q>),
}

impl<I, Q, S, M> RemovableScheduler<I, S> for SupportedSchedulers<Q, M>
where
    Q: Scheduler<I, S> + RemovableScheduler<I, S>,
    M: Scheduler<I, S> + RemovableScheduler<I, S>,
    S: HasTestcase<I> + HasMetadata,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        if let Ok(meta) = state.metadata_mut::<crate::stages::RuntimeMetadata>() {
            meta.remove_metadata(id);
        }
        match self {
            Self::Queue(queue, _) => queue.on_remove(state, id, testcase),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_remove(state, id, testcase),
        }
    }

    fn on_replace(&mut self, state: &mut S, id: CorpusId, prev: &Testcase<I>) -> Result<(), Error> {
        if let Ok(meta) = state.metadata_mut::<crate::stages::RuntimeMetadata>() {
            meta.remove_metadata(id);
        }
        match self {
            Self::Queue(queue, _) => queue.on_replace(state, id, prev),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_replace(state, id, prev),
        }
    }
}

impl<I, Q, S, M> Scheduler<I, S> for SupportedSchedulers<Q, M>
where
    Q: Scheduler<I, S>,
    M: Scheduler<I, S>,
    S: HasCorpus<I> + HasTestcase<I>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        match self {
            // We need to manually set the depth
            // since we want to avoid implementing `AflScheduler` for `QueueScheduler`
            Self::Queue(queue, _) => {
                queue.on_add(state, id)?;
                let current_id = *state.corpus().current();
                let mut depth = match current_id {
                    Some(parent_idx) => state
                        .testcase(parent_idx)?
                        .metadata::<SchedulerTestcaseMetadata>()?
                        .depth(),
                    None => 0,
                };
                depth += 1;
                let mut testcase = state.corpus().get(id)?.borrow_mut();
                testcase.add_metadata(SchedulerTestcaseMetadata::new(depth));
                Ok(())
            }
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_add(state, id),
        }
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        match self {
            Self::Queue(queue, _) => queue.next(state),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.next(state),
        }
    }
    fn on_evaluation<OTB>(&mut self, state: &mut S, input: &I, observers: &OTB) -> Result<(), Error>
    where
        OTB: MatchName,
    {
        match self {
            Self::Queue(queue, _) => queue.on_evaluation(state, input, observers),
            Self::LenTimeMinimizer(minimizer, _) => {
                minimizer.on_evaluation(state, input, observers)
            }
        }
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.set_current_scheduled(state, next_id),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.set_current_scheduled(state, next_id),
        }
    }
}

impl<Q, M> HasQueueCycles for SupportedSchedulers<Q, M>
where
    Q: HasQueueCycles,
    M: HasQueueCycles,
{
    fn queue_cycles(&self) -> u64 {
        match self {
            Self::Queue(queue, _) => queue.queue_cycles(),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.queue_cycles(),
        }
    }
}
