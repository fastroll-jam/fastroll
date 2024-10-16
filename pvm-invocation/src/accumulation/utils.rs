use rjam_common::{Hash32, WorkReport};
use std::collections::{HashMap, HashSet};

type WorkPackageHash = Hash32;
type SegmentRoot = Hash32;

/// Pair of a work report and its unaccumulated dependencies.
type PendingWorkReport = (WorkReport, HashSet<WorkPackageHash>);

/// History of accumulated work packages over EPOCH_LENGTH timeslots.
///
/// Represents `ξ` of the GP.
struct AccumulateHistory {
    items: Vec<HashMap<WorkPackageHash, SegmentRoot>>, // length up to EPOCH_LENGTH
}

/// Queue of work reports pending accumulation due to unresolved dependencies.
///
/// Represents `θ` of the GP.
struct AccumulateQueue {
    items: Vec<Vec<PendingWorkReport>>, // length up to EPOCH_LENGTH
}
