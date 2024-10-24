use crate::error::TransitionError;
use rjam_common::Hash32;
use rjam_state::{StateManager, StateWriteOp};
use std::collections::HashSet;

/// State transition function of `PendingReports`, eliminating invalid work reports.
///
/// # Transitions
///
/// This handles the first state transition for `PendingReports`. With dispute extrinsics introduced
/// in the current block, the disputes system categorizes work reports under judgment into three groups:
/// the `good set`, the `bad set`, and the `wonky set`. This function removes entries that are either
/// in the `bad set` or the `wonky set` from `PendingReports`, ensuring that only valid reports
/// remain, which can later be accumulated into the on-chain state.
pub fn transition_reports_eliminate_invalid(
    state_manager: &StateManager,
    bad_set: &HashSet<Hash32>,
    wonky_set: &HashSet<Hash32>,
) -> Result<(), TransitionError> {
    state_manager.with_mut_pending_reports(StateWriteOp::Update, |pending_reports| {
        for report_hash in bad_set.iter().chain(wonky_set.iter()) {
            pending_reports.remove_by_hash(report_hash).unwrap(); // TODO: proper error handling
        }
    })?;

    Ok(())
}
