use crate::error::TransitionError;
use fr_block::{
    header_db::BlockHeaderDB,
    types::extrinsics::{assurances::AssurancesXt, disputes::DisputesXt, guarantees::GuaranteesXt},
};
use fr_common::{
    workloads::work_report::{ReportedWorkPackage, WorkReport},
    BlockHeaderHash,
};
use fr_crypto::types::Ed25519PubKey;
use fr_extrinsics::validation::{
    assurances::AssurancesXtValidator, disputes::DisputesXtValidator,
    guarantees::GuaranteesXtValidator,
};
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{PendingReport, Timeslot},
};
use std::{collections::HashSet, sync::Arc};

/// State transition function of `PendingReports`, eliminating invalid work reports by consuming
/// the `DisputesXt`.
///
/// # Transitions
///
/// This handles the first state transition for `PendingReports`, yielding `ρ†`.
/// This function removes `PendingReports` entries that are either in the `bad set` or the `wonky set`
/// identified by the disputes system, ensuring that only valid reports remain,
/// which can later be accumulated into the on-chain state.
pub async fn transition_reports_eliminate_invalid(
    state_manager: Arc<StateManager>,
    disputes_xt: &DisputesXt,
    prior_timeslot: Timeslot,
) -> Result<(), TransitionError> {
    tracing::info!(
        "Disputes: {} verdicts, {} culprits, {} faults",
        disputes_xt.verdicts.len(),
        disputes_xt.culprits.len(),
        disputes_xt.faults.len()
    );
    // Validate disputes extrinsic data.
    let disputes_validator = DisputesXtValidator::new(state_manager.clone());
    disputes_validator
        .validate(disputes_xt, &prior_timeslot)
        .await?;

    let (_good_set, bad_set, wonky_set) = disputes_xt.split_report_set();

    state_manager
        .with_mut_pending_reports(
            StateMut::Update,
            |pending_reports| -> Result<(), StateManagerError> {
                for report_hash in bad_set.iter().chain(&wonky_set) {
                    pending_reports.remove_by_hash(report_hash)?;
                }
                Ok(())
            },
        )
        .await?;

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
pub async fn transition_reports_clear_availables(
    state_manager: Arc<StateManager>,
    assurances_xt: &AssurancesXt,
    header_parent_hash: BlockHeaderHash,
) -> Result<Vec<WorkReport>, TransitionError> {
    tracing::info!("Reports: {} assurances xts", assurances_xt.len());
    // Validate assurances extrinsic data.
    let assurances_validator = AssurancesXtValidator::new(state_manager.clone());
    assurances_validator
        .validate(assurances_xt, &header_parent_hash)
        .await?;

    // Get core indices which have been available by introducing the assurances extrinsic.
    let available_reports_core_indices = assurances_xt.available_core_indices();

    // Aggregate work reports to be removed for being available.
    let mut available_reports = Vec::with_capacity(available_reports_core_indices.len());

    let prior_pending_reports = state_manager.get_pending_reports().await?;
    for &core_index in &available_reports_core_indices {
        let report: WorkReport = prior_pending_reports
            .get_by_core_index(core_index)?
            .clone()
            .ok_or(TransitionError::PendingReportMissing(core_index))?
            .work_report;
        available_reports.push(report);
    }

    // Aggregate the core indices of any timed-out reports, so they can be removed silently.
    let current_timeslot = state_manager.get_timeslot().await?;
    let timed_out_core_indices =
        prior_pending_reports.get_timed_out_core_indices(&current_timeslot)?;

    state_manager
        .with_mut_pending_reports(
            StateMut::Update,
            |pending_reports| -> Result<(), StateManagerError> {
                // Remove now-available reports and timed-out reports
                for &core_index in available_reports_core_indices
                    .iter()
                    .chain(&timed_out_core_indices)
                {
                    pending_reports.remove_by_core_index(core_index)?;
                }
                Ok(())
            },
        )
        .await?;

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
/// entry is replaced only if more than `U` timeslots have passed since the report was submitted.
pub async fn transition_reports_update_entries(
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
    guarantees_xt: &GuaranteesXt,
    current_timeslot: Timeslot,
    with_ancestors: bool,
) -> Result<(Vec<ReportedWorkPackage>, HashSet<Ed25519PubKey>), TransitionError> {
    tracing::info!("Reports: {} guarantees xts", guarantees_xt.len());
    // Validate guarantees extrinsic data.
    let guarantees_validator =
        GuaranteesXtValidator::new(state_manager.clone(), header_db, with_ancestors);
    let all_guarantor_keys = guarantees_validator
        .validate(guarantees_xt, current_timeslot.slot())
        .await?;

    let new_valid_reports = guarantees_xt.extract_work_reports();
    state_manager
        .with_mut_pending_reports(
            StateMut::Update,
            |pending_reports| -> Result<(), StateManagerError> {
                for report in &new_valid_reports {
                    pending_reports.0[report.core_index as usize] = Some(PendingReport {
                        work_report: report.clone(),
                        reported_timeslot: current_timeslot,
                    })
                }
                Ok(())
            },
        )
        .await?;

    let reported_packages: Vec<ReportedWorkPackage> = new_valid_reports
        .into_iter()
        .map(|report| ReportedWorkPackage {
            work_package_hash: report.specs.work_package_hash,
            segment_root: report.specs.segment_root,
        })
        .collect();

    Ok((reported_packages, all_guarantor_keys))
}
