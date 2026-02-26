use std::marker::PhantomData;

use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    schedulers::{HasQueueCycles, RemovableScheduler, Scheduler},
    state::HasCorpus,
};
use libafl_bolts::{rands::Rand, tuples::MatchName};

use crate::feedbacks::AssertionMetadata;
use crate::input::IrInput;

use std::num::NonZero;

// ============================================================================
// AssertionDistanceScheduler - prioritizes by assertion distance 50% of time
// ============================================================================

/// A scheduler that 50% of the time prioritizes corpus entries with the best
/// (lowest) assertion distance, and 50% of the time delegates to a fallback scheduler.
///
/// Lower assertion distance = closer to triggering the assertion = higher priority.
///
/// # Safety Guarantees
/// - Never caches `Testcase` references across calls
/// - Always accesses corpus entries fresh via `state.corpus().get(id)`
/// - Handles missing `AssertionMetadata` gracefully (treats as worst priority)
/// - Properly delegates all scheduler lifecycle methods to inner scheduler
/// - Cleans up stale corpus IDs on access (defensive programming)
pub struct AssertionDistanceScheduler<F> {
    /// The fallback scheduler used 50% of the time and for lifecycle delegation
    fallback: F,
    /// Tracks which corpus IDs have assertion metadata for efficient lookup.
    /// IDs of corpus entries that have AssertionMetadata.
    /// Cleaned lazily on iteration if entries become stale.
    tracked_ids: Vec<CorpusId>,
}

impl<F> AssertionDistanceScheduler<F> {
    const DISTANCE_THRESHOLD: u64 = 10;

    pub fn new(fallback: F) -> Self {
        Self {
            fallback,
            tracked_ids: Vec::new(),
        }
    }
}

impl<F> HasQueueCycles for AssertionDistanceScheduler<F>
where
    F: HasQueueCycles,
{
    fn queue_cycles(&self) -> u64 {
        self.fallback.queue_cycles()
    }
}

impl<F, S> RemovableScheduler<IrInput, S> for AssertionDistanceScheduler<F>
where
    F: Scheduler<IrInput, S> + RemovableScheduler<IrInput, S>,
    S: HasTestcase<IrInput> + HasCorpus<IrInput>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<IrInput>>,
    ) -> Result<(), Error> {
        self.tracked_ids.retain(|&i| i != id);
        // Delegate to fallback
        self.fallback.on_remove(state, id, testcase)
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        id: CorpusId,
        prev: &Testcase<IrInput>,
    ) -> Result<(), Error> {
        self.tracked_ids.retain(|&i| i != id);

        // Check if replacement has metadata
        if let Ok(entry) = state.corpus().get(id) {
            if entry.borrow().metadata::<AssertionMetadata>().is_ok() {
                self.tracked_ids.push(id);
            }
        }

        self.fallback.on_replace(state, id, prev)
    }
}

impl<F, S> Scheduler<IrInput, S> for AssertionDistanceScheduler<F>
where
    F: Scheduler<IrInput, S>,
    S: HasCorpus<IrInput> + HasTestcase<IrInput> + libafl::state::HasRand,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        self.fallback.on_add(state, id)?;

        // append_metadata runs before on_add in libafl's flow, so metadata exists
        if let Ok(entry) = state.corpus().get(id) {
            if entry.borrow().metadata::<AssertionMetadata>().is_ok() {
                self.tracked_ids.push(id);
            }
        }

        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            return Err(Error::empty("Corpus is empty"));
        }

        // 50% assertion-based selection
        if state.rand_mut().below(NonZero::new(100).unwrap()) < 50 && !self.tracked_ids.is_empty() {
            if let Some(id) = self.find_assertion_candidate(state) {
                *state.corpus_mut().current_mut() = Some(id);
                return Ok(id);
            }
        }

        self.fallback.next(state)
    }

    fn on_evaluation<OTB>(
        &mut self,
        state: &mut S,
        input: &IrInput,
        observers: &OTB,
    ) -> Result<(), Error>
    where
        OTB: MatchName,
    {
        self.fallback.on_evaluation(state, input, observers)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_id;
        self.fallback.set_current_scheduled(state, next_id)
    }
}

impl<F> AssertionDistanceScheduler<F> {
    /// O(k) where k = tracked entries with assertion metadata.
    /// Handles stale entries gracefully without panic.
    fn find_assertion_candidate<S>(&mut self, state: &mut S) -> Option<CorpusId>
    where
        S: HasCorpus<IrInput> + libafl::state::HasRand,
    {
        let mut entries: Vec<(CorpusId, u64)> = Vec::with_capacity(self.tracked_ids.len());
        let mut stale: Vec<CorpusId> = Vec::new();
        let mut min_dist: Option<u64> = None;

        for &id in &self.tracked_ids {
            // Validate entry still exists
            let entry = match state.corpus().get(id) {
                Ok(e) => e,
                Err(_) => {
                    stale.push(id);
                    continue;
                }
            };

            // Validate metadata still exists and get distance
            let dist = {
                let tc = entry.borrow();
                match tc.metadata::<AssertionMetadata>() {
                    Ok(m) => m.assertions.values().map(|a| a.distance()).sum(),
                    Err(_) => {
                        stale.push(id);
                        continue;
                    }
                }
            };

            min_dist = Some(min_dist.map_or(dist, |m| m.min(dist)));
            entries.push((id, dist));
        }

        // Clean stale entries
        if !stale.is_empty() {
            self.tracked_ids.retain(|id| !stale.contains(id));
        }

        let threshold = min_dist?.saturating_add(Self::DISTANCE_THRESHOLD);

        let eligible: Vec<CorpusId> = entries
            .into_iter()
            .filter(|&(_, d)| d <= threshold)
            .map(|(id, _)| id)
            .collect();

        if eligible.is_empty() {
            return None;
        }

        let idx = state.rand_mut().below(eligible.len() as u64) as usize;
        Some(eligible[idx])
    }
}

// ============================================================================
// SupportedSchedulers enum - wraps different scheduler types
// ============================================================================

pub enum SupportedSchedulers<Q, M> {
    Queue(Q, PhantomData<M>),
    LenTimeMinimizer(M, PhantomData<Q>),
}

impl<Q, S, M> RemovableScheduler<IrInput, S> for SupportedSchedulers<Q, M>
where
    Q: Scheduler<IrInput, S> + RemovableScheduler<IrInput, S>,
    M: Scheduler<IrInput, S> + RemovableScheduler<IrInput, S>,
    S: HasTestcase<IrInput>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<IrInput>>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_remove(state, id, testcase),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_remove(state, id, testcase),
        }
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        id: CorpusId,
        prev: &Testcase<IrInput>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_replace(state, id, prev),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_replace(state, id, prev),
        }
    }
}

impl<Q, S, M> Scheduler<IrInput, S> for SupportedSchedulers<Q, M>
where
    Q: Scheduler<IrInput, S>,
    M: Scheduler<IrInput, S>,
    S: HasCorpus<IrInput> + HasTestcase<IrInput>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        match self {
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

    fn on_evaluation<OTB>(
        &mut self,
        state: &mut S,
        input: &IrInput,
        observers: &OTB,
    ) -> Result<(), Error>
    where
        OTB: MatchName,
    {
        match self {
            Self::Queue(queue, _) => queue.on_evaluation(state, input, observers),
            Self::LenTimeMinimizer(minimizer, _) => minimizer.on_evaluation(state, input, observers),
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
