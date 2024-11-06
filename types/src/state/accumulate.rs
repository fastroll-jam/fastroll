use crate::common::workloads::WorkReport;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Hash32, EPOCH_LENGTH};
use std::collections::{BTreeSet, HashMap};

pub type SegmentRoot = Hash32;
pub type WorkPackageHash = Hash32;
/// Pair of a work report and its unaccumulated dependencies.
pub type DeferredWorkReport = (WorkReport, BTreeSet<WorkPackageHash>);

/// Queue of work reports pending accumulation due to unresolved dependencies.
///
/// Queue entries have fixed indices, by the slot phase `m` within an epoch of length `E`.
///
/// Represents `θ` of the GP.
#[derive(Clone, JamEncode, JamDecode)]
pub struct AccumulateQueue {
    items: Vec<Vec<DeferredWorkReport>>, // length up to EPOCH_LENGTH
}

impl Default for AccumulateQueue {
    fn default() -> Self {
        Self {
            items: vec![Vec::new(); EPOCH_LENGTH],
        }
    }
}

impl AccumulateQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Safely gets the accumulate queue entry at the given signed index.
    /// Implementation of the circular buffer indexing for a queue of length EPOCH_LENGTH.
    pub fn get_circular(&self, index: isize) -> &Vec<DeferredWorkReport> {
        assert_eq!(
            self.items.len(),
            EPOCH_LENGTH,
            "AccumulateQueue must be initialized with EPOCH_LENGTH entries"
        );

        let effective_index = index.rem_euclid(EPOCH_LENGTH as isize) as usize;
        &self.items[effective_index]
    }

    /// Safely gets a mutable reference to the accumulate queue entry at the given signed index.
    /// Implementation of the circular buffer indexing for a queue of length EPOCH_LENGTH.
    pub fn get_circular_mut(&mut self, index: isize) -> &mut Vec<DeferredWorkReport> {
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
        &mut self,
        timeslot_index: u32,
    ) -> Vec<DeferredWorkReport> {
        let slot_phase = timeslot_index as usize % EPOCH_LENGTH;
        let older_entries = self.items.split_off(slot_phase);
        older_entries
            .into_iter()
            .chain(self.items.iter().cloned())
            .flatten()
            .collect()
    }
}

/// History of accumulated work packages over EPOCH_LENGTH timeslots.
///
/// History entries are dynamically indexed. Thus, adding a new history entry will shift the history
/// sequence by one entry, as defined in the `add` method.
///
/// Represents `ξ` of the GP.
#[derive(Clone, JamEncode, JamDecode)]
pub struct AccumulateHistory {
    items: Vec<HashMap<WorkPackageHash, SegmentRoot>>, // length up to EPOCH_LENGTH
}

impl AccumulateHistory {
    /// Returns a union of all HashMaps in the one-epoch worth of history.
    pub fn union(&self) -> HashMap<WorkPackageHash, SegmentRoot> {
        self.items.iter().fold(HashMap::new(), |mut acc, hashmap| {
            acc.extend(hashmap.iter().map(|(k, v)| (*k, *v)));
            acc
        })
    }

    pub fn add(&mut self, entry: HashMap<WorkPackageHash, SegmentRoot>) {
        if self.items.len() < EPOCH_LENGTH {
            self.items.push(entry);
        } else {
            self.items.remove(0);
            self.items.push(entry);
        }
    }
}
