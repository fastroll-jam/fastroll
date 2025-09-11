use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
    types::work_report::WorkReport,
};
use fr_codec::prelude::*;
use fr_common::{TimeslotIndex, WorkPackageHash, EPOCH_LENGTH};
use fr_limited_vec::FixedVec;
use std::{
    collections::BTreeSet,
    fmt::{Display, Formatter},
};

/// Pair of a work report and its unaccumulated dependencies.
pub type WorkReportDepsMap = (WorkReport, BTreeSet<WorkPackageHash>);
pub type AccumulateQueueEntries = FixedVec<Vec<WorkReportDepsMap>, EPOCH_LENGTH>;
pub type AccumulateHistoryEntries = FixedVec<BTreeSet<WorkPackageHash>, EPOCH_LENGTH>;

/// A queue of work reports pending accumulation due to unresolved dependencies.
///
/// The queue entries have fixed indices, by the slot phase `m` within an epoch of length `E`.
///
/// Represents `ω` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccumulateQueue {
    pub items: AccumulateQueueEntries,
}
impl_simple_state_component!(AccumulateQueue, AccumulateQueue);

impl Display for AccumulateQueue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.items.is_empty() {
            writeln!(f, "AccumulateQueue {{}}")?;
            return Ok(());
        }

        writeln!(f, "AccumulateQueue {{")?;
        for entry in self.items.iter() {
            for (report, deps) in entry.iter() {
                writeln!(f, "  Report {{ {} }}", report)?;
                writeln!(f, "  Deps {{")?;
                for dep in deps.iter() {
                    writeln!(f, "    {},", dep)?;
                }
                writeln!(f, "  }},")?;
            }
        }
        write!(f, "}}")
    }
}

impl AccumulateQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Safely gets the accumulate queue entry at the given signed index.
    /// Implements the circular buffer indexing for a queue of length `EPOCH_LENGTH`.
    pub fn get_circular(&self, index: isize) -> &Vec<WorkReportDepsMap> {
        assert_eq!(
            self.items.len(),
            EPOCH_LENGTH,
            "AccumulateQueue must be initialized with EPOCH_LENGTH entries"
        );

        let effective_index = index.rem_euclid(EPOCH_LENGTH as isize) as usize;
        &self.items[effective_index]
    }

    /// Safely gets a mutable reference to the accumulate queue entry at the given signed index.
    /// Implements the circular buffer indexing for a queue of length `EPOCH_LENGTH`.
    pub fn get_circular_mut(&mut self, index: isize) -> &mut Vec<WorkReportDepsMap> {
        assert_eq!(
            self.items.len(),
            EPOCH_LENGTH,
            "AccumulateQueue must be initialized with EPOCH_LENGTH entries"
        );

        let effective_index = index.rem_euclid(EPOCH_LENGTH as isize) as usize;
        &mut self.items[effective_index]
    }

    /// Partitions and flattens the accumulate queue based on the current slot phase `m`.
    /// This function is required to reorder all queue entries in the accumulate queue
    /// by their associated timeslot. Since the accumulate queue entries have **fixed** indices,
    /// entries from index `m` to the end represent the oldest `E - m` entries, followed by
    /// the most recent `m` entries at the beginning of the queue (from index `0` to `m-1`).
    pub fn partition_by_slot_phase_and_flatten(
        &self,
        timeslot_index: TimeslotIndex,
    ) -> Vec<WorkReportDepsMap> {
        let slot_phase = timeslot_index as usize % EPOCH_LENGTH; // m
        let mut queue_ordered = self.items.clone();
        Self::rotate_left_queue(&mut queue_ordered, slot_phase);
        queue_ordered.into_iter().flatten().collect()
    }

    fn rotate_left_queue(queue: &mut AccumulateQueueEntries, mid: usize) {
        queue.as_mut().rotate_left(mid);
    }
}

/// A history of accumulated work packages over `EPOCH_LENGTH` timeslots.
///
/// Represents `ξ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccumulateHistory {
    pub items: AccumulateHistoryEntries,
}
impl_simple_state_component!(AccumulateHistory, AccumulateHistory);

impl Display for AccumulateHistory {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.items.is_empty() {
            writeln!(f, "AccumulateHistory {{}}")?;
            return Ok(());
        }
        writeln!(f, "AccumulateHistory {{")?;
        for entry in self.items.iter() {
            if entry.is_empty() {
                writeln!(f, "  {{}},")?;
                continue;
            }
            writeln!(f, "  {{")?;
            for hash in entry.iter() {
                writeln!(f, "    {hash}")?;
            }
            writeln!(f, "  }},")?;
        }
        write!(f, "}}")
    }
}

impl AccumulateHistory {
    /// Returns a union of all HashMaps in the one-epoch worth of history.
    pub fn union(&self) -> BTreeSet<WorkPackageHash> {
        self.items.iter().flatten().cloned().collect()
    }

    pub fn add(&mut self, entry: BTreeSet<WorkPackageHash>) {
        Self::rotate_left_history(&mut self.items, 1);
        self.items[EPOCH_LENGTH - 1] = entry;
    }

    pub fn last_history(&self) -> Option<&BTreeSet<WorkPackageHash>> {
        self.items.as_ref().last()
    }

    fn rotate_left_history(history: &mut AccumulateHistoryEntries, mid: usize) {
        history.as_mut().rotate_left(mid);
    }
}
