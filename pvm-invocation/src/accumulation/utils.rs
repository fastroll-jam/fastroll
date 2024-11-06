use rjam_common::Address;
use rjam_types::{
    common::{transfers::DeferredTransfer, workloads::WorkReport},
    state::accumulate::{AccumulateQueue, DeferredWorkReport, SegmentRoot, WorkPackageHash},
};
use std::collections::{BTreeSet, HashMap};

/// Represents function `D` of the GP.
fn construct_deferred_reports(report: WorkReport) -> DeferredWorkReport {
    let deps: BTreeSet<WorkPackageHash> = report
        .prerequisite()
        .into_iter()
        .chain(report.segment_roots_lookup().keys().cloned())
        .collect();

    (report, deps)
}

/// Edits the queue of pending work reports based on the accumulated history.
///
/// There are three main operations:
/// 1. Removes work reports that are already in the accumulated history.
/// 2. Removes dependencies that are already in the accumulated history.
/// 3. Removes work reports whose segment roots conflict with the accumulated history.
///
/// As a result, the output queue contains only work reports that:
/// - Are not already accumulated
/// - Have updated dependencies (removing those already accumulated)
/// - Have segment roots that either match or are not present in the accumulated history
///
/// Represents function `E` of the GP.
pub fn edit_queue(
    queue: Vec<DeferredWorkReport>,
    accumulated: &HashMap<WorkPackageHash, SegmentRoot>,
) -> Vec<DeferredWorkReport> {
    queue
        .into_iter()
        .filter(|(report, _)| !accumulated.contains_key(&report.work_package_hash()))
        .map(|(report, deps)| {
            let edited_deps: BTreeSet<WorkPackageHash> = deps
                .into_iter()
                .filter(|dep| !accumulated.contains_key(dep))
                .collect();
            (report, edited_deps)
        })
        .filter(|(report, _)| {
            let lookup = report.segment_roots_lookup();
            lookup
                .iter()
                .all(|(k, v)| accumulated.get(k).map_or(true, |acc_v| acc_v == v))
        })
        .collect()
}

/// Returns work reports ready for accumulation, recursively resolving dependencies.
///
/// Steps:
/// 1. Collects work reports with no dependencies.
/// 2. Updates the accumulatable history with these reports.
/// 3. Edits the remaining queue to reflect the new accumulatables.
/// 4. Recursively processes the edited queue to find work reports that became free of dependencies.
/// 5. Continues until no more reports can be accumulated.
///
/// Represents function `Q` of the GP.
fn filter_accumulatable_deferred_reports(
    queue: Vec<DeferredWorkReport>,
    accumulated: &mut HashMap<WorkPackageHash, SegmentRoot>,
) -> Vec<WorkReport> {
    let accumulatable: Vec<WorkReport> = queue
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(report, _)| report.clone())
        .collect();

    if accumulatable.is_empty() {
        Vec::new()
    } else {
        let accumulatable_history = map_segment_roots(&accumulatable);
        accumulated.extend(accumulatable_history.iter().map(|(k, v)| (*k, *v)));

        let mut result = accumulatable;
        let edited_queue = edit_queue(queue, &accumulatable_history);
        result.extend(filter_accumulatable_deferred_reports(
            edited_queue,
            accumulated,
        ));
        result
    }
}

/// Builds a dictionary of work package hashes to segment-roots from a set of work reports.
///
/// Represents function `P` of the GP.
pub fn map_segment_roots(reports: &[WorkReport]) -> HashMap<WorkPackageHash, SegmentRoot> {
    reports
        .iter()
        .map(|report| (report.work_package_hash(), report.segment_root()))
        .collect()
}

/// Partitions available work reports into two groups based on the presence of dependencies.
///
/// Implements partitioning available reports `W` into `W^!` and `W^Q` as described in the GP.
pub fn partition_reports_by_dependencies(
    available_reports: Vec<WorkReport>,
) -> (Vec<WorkReport>, Vec<WorkReport>) {
    let (without_deps, with_deps) = available_reports.into_iter().partition(|report| {
        report.prerequisite().is_none() && report.segment_roots_lookup().is_empty()
    });

    (without_deps, with_deps)
}

/// Processes work reports with dependencies, constructing deferred work reports and editing the queue.
///
/// The output represents `W^Q` of the GP.
fn filter_deferred_reports(
    reports_with_deps: Vec<WorkReport>,
    unique_history: &HashMap<WorkPackageHash, SegmentRoot>,
) -> Vec<DeferredWorkReport> {
    edit_queue(
        reports_with_deps
            .into_iter()
            .map(construct_deferred_reports)
            .collect(),
        unique_history,
    )
}

/// Processes all available work reports, combining immediately accumulatable reports with
/// those that become accumulatable after resolving dependencies.
///
/// The output represents `W^*` of the GP.
pub fn process_accumulatable_reports(
    available_reports: Vec<WorkReport>,
    accumulate_queue: &mut AccumulateQueue,
    unique_history: HashMap<WorkPackageHash, SegmentRoot>,
    header_timeslot_index: u32,
) -> Vec<WorkReport> {
    let (mut accumulatable_reports, reports_with_deps) =
        partition_reports_by_dependencies(available_reports);

    // Represents `P(W^!)`
    let new_accumulated = map_segment_roots(&accumulatable_reports);

    let queue: Vec<_> = accumulate_queue
        .partition_by_slot_phase_and_flatten(header_timeslot_index)
        .into_iter()
        .chain(filter_deferred_reports(reports_with_deps, &unique_history))
        .collect();

    let edited_queue = edit_queue(queue.clone(), &new_accumulated);

    let mut history_union: HashMap<_, _> =
        unique_history.into_iter().chain(new_accumulated).collect();

    let mut new_accumulatables =
        filter_accumulatable_deferred_reports(edited_queue, &mut history_union);

    accumulatable_reports.append(&mut new_accumulatables);
    accumulatable_reports
}

/// Selects and sorts deferred transfers for a specific `destination`.
///
/// First it filters transfers by the given destination address, then sorts them
/// primarily by the `from` address and secondarily by their original order in the input slice.
///
/// Represents function `R` of the GP.
pub fn select_deferred_transfers(
    transfers: &[DeferredTransfer],
    destination: Address,
) -> Vec<DeferredTransfer> {
    let mut selected: Vec<_> = transfers
        .iter()
        .enumerate()
        .filter(|(_, transfer)| transfer.to == destination)
        .collect();
    selected.sort_by_key(|&(i, transfer)| (transfer.from, i));
    selected
        .into_iter()
        .map(|(_, transfer)| *transfer)
        .collect()
}
