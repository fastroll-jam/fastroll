use crate::error::TransitionError;
use rjam_common::{Ed25519PubKey, Hash32};
use rjam_extrinsics::validation::{
    assurances::AssurancesXtValidator, disputes::DisputesXtValidator,
    guarantees::GuaranteesXtValidator,
};
use rjam_state::{StateManager, StateMut};
use rjam_types::{
    common::workloads::WorkReport,
    extrinsics::{assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt},
    state::*,
};

/// State transition function of `PendingReports`, eliminating invalid work reports by consuming
/// the `DisputesXt`.
///
/// # Transitions
///
/// This handles the first state transition for `PendingReports`, yielding `ρ†`.
/// With dispute extrinsic introduced in the current block, the disputes system categorizes
/// work reports under judgment into three groups: the `good set`, the `bad set`, and the `wonky set`.
/// This function removes entries that are either in the `bad set` or the `wonky set` from
/// `PendingReports`, ensuring that only valid reports remain, which can later be accumulated into
/// the on-chain state.
pub fn transition_reports_eliminate_invalid(
    state_manager: &StateManager,
    disputes: &DisputesXt,
    prior_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    // Validate disputes extrinsic data.
    let disputes_validator = DisputesXtValidator::new(state_manager);
    disputes_validator.validate(disputes, prior_timeslot)?;

    let (_good_set, bad_set, wonky_set) = disputes.split_report_set();

    state_manager.with_mut_pending_reports(StateMut::Update, |pending_reports| {
        for report_hash in bad_set.iter().chain(wonky_set.iter()) {
            pending_reports.remove_by_hash(report_hash).unwrap(); // TODO: proper error handling
        }
    })?;

    Ok(())
}

/// State transition function of `PendingReports`, removing work reports that are now available for
/// the accumulation by consuming the `AssurancesXt`. It also removes timed-out entries.
///
/// # Transitions
///
/// This handles the second state transition for `PendingReports`, yielding `ρ‡`.
/// Reports receiving assurances from more than two-thirds of the validators in the current block
/// become available for accumulation. Since `PendingReports` holds at most one report per core
/// awaiting this condition, it removes entries as soon as they qualify to maintain an efficient state.
pub fn transition_reports_clear_availables(
    state_manager: &StateManager,
    assurances: &AssurancesXt,
    header_parent_hash: &Hash32,
) -> Result<Vec<WorkReport>, TransitionError> {
    // Validate assurances extrinsic data.
    let assurances_validator = AssurancesXtValidator::new(state_manager);
    assurances_validator.validate(assurances, header_parent_hash)?;

    // Get core indices which have been available by introducing the assurances extrinsic.
    let available_reports_core_indices = assurances.available_core_indices();

    // Aggregate work reports to be removed for being available.
    let mut available_reports = Vec::with_capacity(available_reports_core_indices.len());

    let prior_pending_reports = state_manager.get_pending_reports()?;
    for core_index in &available_reports_core_indices {
        let report: WorkReport = prior_pending_reports
            .get_by_core_index(*core_index)?
            .clone()
            .expect("Core index verified to have pending report")
            .work_report;
        available_reports.push(report);
    }

    // Aggregate the core indices of any timed-out reports so they can be removed silently.
    let current_timeslot = state_manager.get_timeslot()?;
    let timed_out_core_indices =
        prior_pending_reports.get_timed_out_core_indices(&current_timeslot)?;

    state_manager.with_mut_pending_reports(StateMut::Update, |pending_reports| {
        // Remove now-available reports and timed-out reports
        for core_index in available_reports_core_indices
            .iter()
            .chain(timed_out_core_indices.iter())
        {
            pending_reports.remove_by_core_index(*core_index).unwrap()
        }
    })?;

    Ok(available_reports)
}

/// State transition function of `PendingReports`, adding new reports or replacing those that
/// have timed out, based on reports introduced in this block’s `GuaranteesXt`.
///
/// # Transitions
///
/// This handles the final state transition for `PendingReports`, yielding `ρ′`.
/// New work reports from the guarantees extrinsic can be added to `PendingReports`.
/// If a core's slot is empty, the new report fills it. If the slot is occupied, the existing
/// entry is replaced only if more than `U = 5` timeslots have passed since the report was submitted.
///
/// # Return
/// (Vec<(`work_package_hash`, `segments_root`)>, Vec<`reporter_ed25519_key`>) // TODO: update type
#[allow(clippy::type_complexity)]
pub fn transition_reports_update_entries(
    state_manager: &StateManager,
    guarantees: &GuaranteesXt,
    current_timeslot: &Timeslot,
) -> Result<(Vec<(Hash32, Hash32)>, Vec<Ed25519PubKey>), TransitionError> {
    // Validate guarantees extrinsic data.
    let guarantees_validator = GuaranteesXtValidator::new(state_manager);
    let all_guarantor_keys = guarantees_validator.validate(guarantees, current_timeslot.slot())?;

    let new_valid_reports = guarantees.extract_work_reports();
    state_manager.with_mut_pending_reports(StateMut::Update, |pending_reports| {
        for report in &new_valid_reports {
            pending_reports.0[report.core_index() as usize] = Some(PendingReport {
                work_report: report.clone(),
                reported_timeslot: *current_timeslot,
            })
        }
    })?;

    let reported_packages: Vec<(Hash32, Hash32)> = new_valid_reports
        .into_iter()
        .map(|report| (report.specs.work_package_hash, report.specs.segment_root))
        .collect();

    Ok((reported_packages, all_guarantor_keys))
}
