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
/// Maintains a sorted vec of (CorpusId, distance) for O(log n) candidate selection
/// instead of O(n) full scans. Distances are cached at insert time.
pub struct AssertionDistanceScheduler<F> {
    /// The fallback scheduler used 50% of the time and for lifecycle delegation
    fallback: F,
    /// Entries sorted by distance ascending. Index 0 has minimum distance.
    /// Tuple is (CorpusId, cached_distance).
    tracked_entries: Vec<(CorpusId, u64)>,
}

impl<F> AssertionDistanceScheduler<F> {
    const MIN_CANDIDATES: usize = 16;

    pub fn new(fallback: F) -> Self {
        Self {
            fallback,
            tracked_entries: Vec::new(),
        }
    }

    /// Compute distance from metadata. Returns None if assertions map is empty,
    /// which fixes the bug where empty metadata was treated as distance 0.
    fn compute_distance(metadata: &AssertionMetadata) -> Option<u64> {
        if metadata.assertions.is_empty() {
            return None;
        }
        Some(metadata.assertions.values().map(|a| a.distance()).sum())
    }

    /// Insert entry maintaining sorted order by distance. O(log n) search + O(n) insert,
    /// but inserts are infrequent compared to selections.
    fn insert_tracked(&mut self, id: CorpusId, distance: u64) {
        let pos = self
            .tracked_entries
            .binary_search_by_key(&distance, |&(_, d)| d)
            .unwrap_or_else(|p| p);
        self.tracked_entries.insert(pos, (id, distance));
    }

    /// Remove entry by CorpusId. O(n) but removals are rare.
    fn remove_tracked(&mut self, id: CorpusId) {
        if let Some(pos) = self.tracked_entries.iter().position(|&(eid, _)| eid == id) {
            self.tracked_entries.remove(pos);
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
        self.remove_tracked(id);
        self.fallback.on_remove(state, id, testcase)
    }

    fn on_replace(
        &mut self,
        state: &mut S,
        id: CorpusId,
        prev: &Testcase<IrInput>,
    ) -> Result<(), Error> {
        // Remove old entry first
        self.remove_tracked(id);

        // Check if replacement has valid metadata and reinsert with new distance
        if let Ok(entry) = state.corpus().get(id) {
            let tc = entry.borrow();
            if let Ok(metadata) = tc.metadata::<AssertionMetadata>() {
                if let Some(distance) = Self::compute_distance(metadata) {
                    self.insert_tracked(id, distance);
                }
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

        // Compute and cache distance at add time
        if let Ok(entry) = state.corpus().get(id) {
            let tc = entry.borrow();
            if let Ok(metadata) = tc.metadata::<AssertionMetadata>() {
                if let Some(distance) = Self::compute_distance(metadata) {
                    self.insert_tracked(id, distance);
                }
            }
        }

        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            return Err(Error::empty("Corpus is empty"));
        }

        // 50% assertion-based selection
        if state.rand_mut().below(NonZero::new(100).unwrap()) < 50
            && !self.tracked_entries.is_empty()
        {
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
    /// O(log n) candidate selection using cached distances and binary search.
    /// Verifies selected entry exists; removes stale entries lazily.
    fn find_assertion_candidate<S>(&mut self, state: &mut S) -> Option<CorpusId>
    where
        S: HasCorpus<IrInput> + libafl::state::HasRand,
    {
        loop {
            if self.tracked_entries.is_empty() {
                return None;
            }

            // Pick from the top 25% of entries by distance, but always at least
            // MIN_CANDIDATES so one outlier input can't starve the pool.
            let cutoff = (self.tracked_entries.len() / 4)
                .max(Self::MIN_CANDIDATES)
                .min(self.tracked_entries.len());

            // Random selection from eligible entries [0, cutoff)
            let idx = state.rand_mut().below(NonZero::new(cutoff).unwrap());
            let (id, _) = self.tracked_entries[idx];

            // Defensive: verify entry still exists in corpus
            if state.corpus().get(id).is_ok() {
                return Some(id);
            }

            // Entry is stale (removed from corpus without on_remove call), remove and retry
            self.tracked_entries.remove(idx);
        }
    }
}

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

    fn on_replace(&mut self, state: &mut S, id: CorpusId, prev: &Testcase<IrInput>) -> Result<(), Error> {
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
    fn on_evaluation<OTB>(&mut self, state: &mut S, input: &IrInput, observers: &OTB) -> Result<(), Error>
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
