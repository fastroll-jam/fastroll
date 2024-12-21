use crate::error::TransitionError;
use rjam_common::CoreIndex;
use rjam_extrinsics::validation::disputes::DisputesExtrinsicValidator;
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::{
    common::workloads::WorkReport, extrinsics::disputes::DisputesExtrinsic, state::*,
};

/// State transition function of `PendingReports`, eliminating invalid work reports by consuming
/// the `DisputesExtrinsic`.
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
    disputes: &DisputesExtrinsic,
    prior_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let disputes_validator = DisputesExtrinsicValidator::new(state_manager);
    disputes_validator.validate(disputes, prior_timeslot)?;

    let (_good_set, bad_set, wonky_set) = disputes.split_report_set();

    state_manager.with_mut_pending_reports(StateWriteOp::Update, |pending_reports| {
        for report_hash in bad_set.iter().chain(wonky_set.iter()) {
            pending_reports.remove_by_hash(report_hash).unwrap(); // TODO: proper error handling
        }
    })?;

    Ok(())
}

/// State transition function of `PendingReports`, removing work reports that are now available for
/// the accumulation by consuming the `AssurancesExtrinsic`.
///
/// # Transitions
///
/// This handles the second state transition for `PendingReports`, yielding `ρ‡`.
/// Reports receiving assurances from more than two-thirds of the validators in the current block
/// become available for accumulation. Since `PendingReports` holds at most one report per core
/// awaiting this condition, it removes entries as soon as they qualify to maintain an efficient state.
pub fn transition_reports_clear_availables(
    state_manager: &StateManager,
    available_reports_core_indices: &[CoreIndex],
) -> Result<(), TransitionError> {
    state_manager.with_mut_pending_reports(StateWriteOp::Update, |pending_reports| {
        for core_index in available_reports_core_indices {
            pending_reports.remove_by_core_index(*core_index).unwrap()
        }
    })?;

    Ok(())
}

/// State transition function of `PendingReports`, replacing timed-out entries with new reports
/// introduced in this block by consuming the `GuaranteesExtrinsic`.
///
/// # Transitions
///
/// This handles the final state transition for `PendingReports`, yielding `ρ′`.
/// New work reports from the guarantees extrinsic can be added to `PendingReports`.
/// If a core's slot is empty, the new report fills it. If the slot is occupied, the existing
/// entry is replaced only if more than `U = 5` timeslots have passed since the report was submitted.
pub fn transition_reports_replace_entries(
    state_manager: &StateManager,
    new_valid_reports: &[WorkReport],
    current_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    state_manager.with_mut_pending_reports(StateWriteOp::Update, |pending_reports| {
        for report in new_valid_reports {
            pending_reports.0[report.core_index() as usize] = Some(PendingReport {
                work_report: report.clone(),
                timeslot: *current_timeslot,
            })
        }
    })?;

    Ok(())
}
