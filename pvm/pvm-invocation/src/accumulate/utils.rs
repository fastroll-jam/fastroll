use fr_common::{workloads::work_report::WorkReport, ServiceId, TimeslotIndex, WorkPackageHash};
use fr_pvm_types::invoke_args::DeferredTransfer;
use fr_state::types::{
    accumulate::{AccumulateQueue, WorkReportDepsMap},
    AccumulateHistory,
};

/// Accumulatable work reports in this block.
/// Represents **`R^!`** of the GP.
pub type AccumulatableReports = Vec<WorkReport>;
/// Pairs of newly queued work reports and their dependencies.
/// Represents **`R^Q`** of the GP.
pub type QueuedReports = Vec<WorkReportDepsMap>;

/// Returns a tuple of the given work report and its dependencies; prerequisite package hashes
/// and segment lookup dictionary keys included in the report.
///
/// Represents function *`D`* of the GP.
fn work_report_deps(report: &WorkReport) -> WorkReportDepsMap {
    let mut deps = report.prerequisites().clone();
    deps.extend(report.segment_roots_lookup.keys().cloned());

    (report.clone(), deps)
}

/// Edits the accumulation queue based on the newly accumulated work package hashes.
///
/// An accumulation queue item consists of a work report awaiting accumulation and its unaccumulated
/// dependencies, represented as work package hashes. When newly accumulated work packages are
/// introduced, the corresponding work reports and dependency items are removed from the queue.
///
/// Represents function *`E`* of the GP.
pub fn edit_queue(
    queue: &[WorkReportDepsMap],
    new_accumulated_packages: &[WorkPackageHash],
) -> Vec<WorkReportDepsMap> {
    queue
        .iter()
        .filter(|(wr, _)| !new_accumulated_packages.contains(wr.work_package_hash()))
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .map(|(wr, deps)| {
            (
                wr,
                deps.iter()
                    .filter(|&wph| !new_accumulated_packages.contains(wph))
                    .cloned()
                    .collect(),
            )
        })
        .collect()
}

/// Extracts work reports ready for accumulation from the given not-yet-accumulated work reports set,
/// recursively resolving dependencies.
///
/// Represents function *`Q`* of the GP.
fn extract_accumulatables(queue: &[WorkReportDepsMap]) -> Vec<WorkReport> {
    let no_deps = queue
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .cloned()
        .map(|(wr, _)| wr)
        .collect::<Vec<_>>();
    if no_deps.is_empty() {
        return vec![];
    }

    let deps_resolved =
        extract_accumulatables(&edit_queue(queue, &reports_to_package_hashes(&no_deps)));

    no_deps.into_iter().chain(deps_resolved).collect()
}

/// Extracts the corresponding work package hashes from the given work reports.
///
/// Represents function *`P`* of the GP.
pub fn reports_to_package_hashes(reports: &[WorkReport]) -> Vec<WorkPackageHash> {
    reports
        .iter()
        .map(|wr| wr.work_package_hash().clone())
        .collect()
}

/// Partitions available work reports into two groups based on the presence of dependencies.
///
/// This function is used for partitioning available reports **`R`** into
/// **`R^!`** and **`R^Q`** of the GP.
pub fn partition_reports_by_deps(
    available_reports: Vec<WorkReport>,
) -> (Vec<WorkReport>, Vec<WorkReport>) {
    let (no_deps, with_deps) = available_reports
        .into_iter()
        .partition(|wr| wr.prerequisites().is_empty() && wr.segment_roots_lookup.is_empty());

    (no_deps, with_deps)
}

/// Extracts queued work reports from the available reports set.
///
/// The output represents **`R^Q`** of the GP.
fn extract_queued_reports(
    reports_with_deps: &[WorkReport],
    accumulate_history_union: &[WorkPackageHash],
) -> Vec<WorkReportDepsMap> {
    edit_queue(
        reports_with_deps
            .iter()
            .cloned()
            .map(|wr| work_report_deps(&wr))
            .collect::<Vec<_>>()
            .as_slice(),
        accumulate_history_union,
    )
}

/// Returns accumulatable work reports in this block, including reports with no dependency and
/// queue reports that became accumulatable after their dependencies getting resolved.
///
/// The output represents a pair of (**`R^*`**, **`R^Q`**).
pub fn collect_accumulatable_reports(
    available_reports: Vec<WorkReport>,
    accumulate_queue: &AccumulateQueue,
    accumulate_history: &AccumulateHistory,
    timeslot_index: TimeslotIndex,
) -> (AccumulatableReports, QueuedReports) {
    let (mut accumulatables, reports_with_deps) = partition_reports_by_deps(available_reports);
    let mut queue = accumulate_queue.partition_by_slot_phase_and_flatten(timeslot_index);

    let new_reports_queued = extract_queued_reports(
        &reports_with_deps,
        accumulate_history
            .union()
            .into_iter()
            .collect::<Vec<_>>()
            .as_slice(),
    );

    queue.extend(new_reports_queued.clone());

    let queue_resolved = extract_accumulatables(&edit_queue(
        &queue,
        &reports_to_package_hashes(&accumulatables),
    ));

    accumulatables.extend(queue_resolved);
    (accumulatables, new_reports_queued)
}

/// Selects and sorts deferred transfers for a specific `destination`.
///
/// First it filters transfers by the given destination address, then sorts them
/// primarily by the `from` address and secondarily by their original order in the input slice.
///
/// Represents function *`R`* of the GP.
pub fn select_deferred_transfers(
    transfers: &[DeferredTransfer],
    destination: ServiceId,
) -> Vec<DeferredTransfer> {
    let mut selected = transfers
        .iter()
        .filter(|&t| t.to == destination)
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by_key(|t| t.from); // order within the input slice is preserved

    selected
}
