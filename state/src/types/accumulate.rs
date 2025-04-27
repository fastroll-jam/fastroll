use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
    types::work_report::WorkReport,
};
use rjam_codec::prelude::*;
use rjam_common::{Hash32, EPOCH_LENGTH};
use std::{array::from_fn, collections::BTreeSet};

pub type SegmentRoot = Hash32;
pub type WorkPackageHash = Hash32;
/// Pair of a work report and its unaccumulated dependencies.
pub type WorkReportDepsMap = (WorkReport, BTreeSet<WorkPackageHash>);

/// A queue of work reports pending accumulation due to unresolved dependencies.
///
/// The queue entries have fixed indices, by the slot phase `m` within an epoch of length `E`.
///
/// Represents `θ` of the GP.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccumulateQueue {
    pub items: Box<[Vec<WorkReportDepsMap>; EPOCH_LENGTH]>,
}
impl_simple_state_component!(AccumulateQueue, AccumulateQueue);

impl Default for AccumulateQueue {
    fn default() -> Self {
        let arr = from_fn(|_| Vec::with_capacity(EPOCH_LENGTH));
        Self {
            items: Box::new(arr),
        }
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
        timeslot_index: u32,
    ) -> Vec<WorkReportDepsMap> {
        let slot_phase = timeslot_index as usize % EPOCH_LENGTH; // m
        let mut queue_ordered = self.items.clone();
        queue_ordered.rotate_left(slot_phase);
        queue_ordered.into_iter().flatten().collect()
    }
}

/// A history of accumulated work packages over `EPOCH_LENGTH` timeslots.
///
/// Represents `ξ` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccumulateHistory {
    pub items: Box<[BTreeSet<WorkPackageHash>; EPOCH_LENGTH]>,
}
impl_simple_state_component!(AccumulateHistory, AccumulateHistory);

impl AccumulateHistory {
    /// Returns a union of all HashMaps in the one-epoch worth of history.
    pub fn union(&self) -> BTreeSet<WorkPackageHash> {
        self.items.iter().flatten().cloned().collect()
    }

    pub fn add(&mut self, entry: BTreeSet<WorkPackageHash>) {
        self.items.rotate_left(1);
        self.items[EPOCH_LENGTH - 1] = entry;
    }

    pub fn last_history(&self) -> Option<&BTreeSet<WorkPackageHash>> {
        self.items.last()
    }
}
