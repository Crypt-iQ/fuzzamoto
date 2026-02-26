use std::cell::RefCell;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::rc::Rc;

use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    schedulers::{HasQueueCycles, RemovableScheduler, Scheduler},
    state::{HasCorpus, HasRand},
};
use libafl_bolts::rands::Rand;
use libafl_bolts::tuples::MatchName;

pub enum SupportedSchedulers<Q, M> {
    Queue(Q, PhantomData<M>),
    LenTimeMinimizer(M, PhantomData<Q>),
}

impl<I, Q, S, M> RemovableScheduler<I, S> for SupportedSchedulers<Q, M>
where
    Q: Scheduler<I, S> + RemovableScheduler<I, S>,
    M: Scheduler<I, S> + RemovableScheduler<I, S>,
    S: HasTestcase<I>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_remove(state, id, testcase),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_remove(state, id, testcase),
        }
    }

    fn on_replace(&mut self, state: &mut S, id: CorpusId, prev: &Testcase<I>) -> Result<(), Error> {
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

/// A shared channel through which `AssertionFeedback` notifies the scheduler
/// about new assertion-bearing corpus entries. This avoids the scheduler calling
/// `corpus().get()` which can cause cache eviction in `CachedOnDiskCorpus` and
/// corrupt internal state.
pub type AssertionChannel = Rc<RefCell<Vec<(CorpusId, u64)>>>;

/// Create a new shared assertion channel.
pub fn new_assertion_channel() -> AssertionChannel {
    Rc::new(RefCell::new(Vec::new()))
}

/// Wraps any scheduler and biases `next()` toward corpus entries that improved
/// assertion distance (i.e. have `AssertionMetadata`). With probability
/// `bias_probability`, a random entry whose distance is within `distance_window`
/// of the current best is returned instead of delegating to the inner scheduler.
///
/// Entries are received via a shared `AssertionChannel` that
/// `AssertionFeedback::append_metadata` pushes into, so the scheduler never
/// needs to call `corpus().get()`.
pub struct AssertionBiasedScheduler<Inner> {
    inner: Inner,
    /// (corpus_id, min_distance_at_insertion)
    assertion_entries: Vec<(CorpusId, u64)>,
    best_distance: u64,
    bias_probability: f64,
    distance_window: u64,
    /// Shared channel fed by AssertionFeedback
    channel: AssertionChannel,
}

impl<Inner> AssertionBiasedScheduler<Inner> {
    pub fn new(inner: Inner, bias_probability: f64, distance_window: u64, channel: AssertionChannel) -> Self {
        Self {
            inner,
            assertion_entries: Vec::new(),
            best_distance: u64::MAX,
            bias_probability,
            distance_window,
            channel,
        }
    }

    /// Drain any entries that the feedback has pushed since our last check.
    fn drain_channel(&mut self) {
        let mut ch = self.channel.borrow_mut();
        for (id, dist) in ch.drain(..) {
            if self.assertion_entries.iter().any(|(eid, _)| *eid == id) {
                continue;
            }
            if dist < self.best_distance {
                self.best_distance = dist;
            }
            self.assertion_entries.push((id, dist));
        }
    }
}

impl<I, S, Inner> Scheduler<I, S> for AssertionBiasedScheduler<Inner>
where
    Inner: Scheduler<I, S>,
    S: HasCorpus<I> + HasTestcase<I> + HasRand,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        self.inner.on_add(state, id)?;
        // Drain any entries that arrived via the channel (from previous add cycles).
        // The entry for `id` itself won't be in the channel yet because
        // append_metadata hasn't run, but earlier entries will be.
        self.drain_channel();
        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        // Drain entries that the feedback pushed since our last call.
        self.drain_channel();

        // Only consider entries within distance_window of the current best
        let eligible: Vec<CorpusId> = self
            .assertion_entries
            .iter()
            .filter(|(_, dist)| *dist <= self.best_distance + self.distance_window)
            .map(|(id, _)| *id)
            .collect();

        if let Some(len) = NonZeroUsize::new(eligible.len()) {
            if state.rand_mut().coinflip(self.bias_probability) {
                let idx = state.rand_mut().below(len);
                let id = eligible[idx];
                self.set_current_scheduled(state, Some(id))?;
                return Ok(id);
            }
        }
        self.inner.next(state)
    }

    fn on_evaluation<OTB>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OTB,
    ) -> Result<(), Error>
    where
        OTB: MatchName,
    {
        self.inner.on_evaluation(state, input, observers)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.inner.set_current_scheduled(state, next_id)
    }
}

impl<I, S, Inner> RemovableScheduler<I, S> for AssertionBiasedScheduler<Inner>
where
    Inner: RemovableScheduler<I, S>,
    S: HasCorpus<I> + HasTestcase<I> + HasRand,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.assertion_entries.retain(|(eid, _)| *eid != id);
        self.inner.on_remove(state, id, testcase)
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        id: CorpusId,
        prev: &Testcase<I>,
    ) -> Result<(), Error> {
        self.inner.on_replace(state, id, prev)
    }
}

impl<Inner> HasQueueCycles for AssertionBiasedScheduler<Inner>
where
    Inner: HasQueueCycles,
{
    fn queue_cycles(&self) -> u64 {
        self.inner.queue_cycles()
    }
}
