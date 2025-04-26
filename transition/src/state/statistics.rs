use crate::error::TransitionError;
use rjam_block::types::extrinsics::{
    assurances::AssurancesXt, guarantees::GuaranteesXt, preimages::PreimagesXt, Extrinsics,
};
use rjam_common::{workloads::WorkReport, CoreIndex, ValidatorIndex, SEGMENT_SIZE};
use rjam_crypto::types::get_validator_ed25519_key_by_index;
use rjam_pvm_types::stats::{AccumulateStats, OnTransferStats};
use rjam_state::{
    cache::StateMut,
    manager::StateManager,
    types::{CoreStats, ServiceStats},
};
use std::sync::Arc;

/// State transition function of `OnChainStatistics`
pub async fn transition_onchain_statistics(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
    header_block_author_index: ValidatorIndex,
    xts: &Extrinsics,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        handle_new_epoch_transition(state_manager.clone()).await?;
    }

    // Validator stats accumulator transition (the first entry of the `ValidatorStats`)
    handle_validator_stats_accumulation(state_manager.clone(), header_block_author_index, xts)
        .await?;
    // FIXME: Available reports, accumulate stats and on-transfer stats should be passes as args of the stats STF.
    let available_reports: Vec<WorkReport> = Vec::new();
    let accumulate_stats: AccumulateStats = AccumulateStats::default();
    let on_transfer_stats: OnTransferStats = OnTransferStats::default();
    handle_per_block_transition(
        state_manager,
        &xts.assurances,
        &xts.guarantees,
        &xts.preimages,
        &available_reports,
        &accumulate_stats,
        &on_transfer_stats,
    )
    .await?;

    Ok(())
}

async fn handle_new_epoch_transition(
    state_manager: Arc<StateManager>,
) -> Result<(), TransitionError> {
    let stats = state_manager.get_onchain_statistics().await?;
    let prior_current_epoch_stats = stats.validator_stats.current_epoch_stats();

    state_manager
        .with_mut_onchain_statistics(StateMut::Update, |stats| {
            stats
                .validator_stats
                .replace_previous_epoch_stats(prior_current_epoch_stats.clone());
            stats.validator_stats.clear_current_epoch_stats();
        })
        .await?;

    Ok(())
}

async fn handle_validator_stats_accumulation(
    state_manager: Arc<StateManager>,
    header_block_author_index: ValidatorIndex,
    xts: &Extrinsics,
) -> Result<(), TransitionError> {
    let current_active_set = state_manager.get_active_set().await?;

    state_manager
        .with_mut_onchain_statistics(StateMut::Update, |stats| {
            let current_epoch_author_stats = stats
                .validator_stats
                .current_epoch_validator_stats_mut(header_block_author_index);

            current_epoch_author_stats.blocks_produced_count += 1;
            current_epoch_author_stats.tickets_count += xts.tickets.len() as u32;
            current_epoch_author_stats.preimages_count += xts.preimages.len() as u32;
            current_epoch_author_stats.preimage_data_octets_count +=
                xts.preimages.total_preimage_data_len() as u32;

            for (validator_index, validator_stats) in stats
                .validator_stats
                .current_epoch_stats_mut()
                .iter_mut()
                .enumerate()
            {
                let validator_index = validator_index as ValidatorIndex;
                let validator_ed25519_key =
                    get_validator_ed25519_key_by_index(&current_active_set, validator_index)
                        .expect("validator index cannot be out of bound here");

                // Update `guarantees_count` if the current validator's Ed25519 public key is in reporters set.
                if xts
                    .guarantees
                    .extract_reporters(&current_active_set)
                    .iter()
                    .any(|reporter| reporter == validator_ed25519_key)
                {
                    validator_stats.guarantees_count += 1;
                }

                // Update `assurances_count` if the current validator submitted assurances extrinsic entry.
                if xts
                    .assurances
                    .contains_assurance_for_validator(validator_index)
                {
                    validator_stats.assurances_count += 1;
                }
            }
        })
        .await?;

    Ok(())
}

async fn handle_per_block_transition(
    state_manager: Arc<StateManager>,
    assurances: &AssurancesXt,
    guarantees: &GuaranteesXt,
    preimages: &PreimagesXt,
    available_reports: &[WorkReport],
    accumulate_stats: &AccumulateStats,
    on_transfer_stats: &OnTransferStats,
) -> Result<(), TransitionError> {
    // Update core stats
    let mut core_stats = CoreStats::default();
    for report in guarantees.extract_work_reports() {
        let entry = core_stats.core_stats_entry_mut(report.core_index);
        entry.work_bundle_length += report.specs.work_bundle_length;
        for digest in report.digests {
            entry.accumulate_refine_stats(&digest.refine_stats);
        }
    }
    for report in available_reports {
        let entry = core_stats.core_stats_entry_mut(report.core_index);
        entry.da_items_size += report.specs.work_bundle_length
            + SEGMENT_SIZE as u32 * 65 * (report.specs.segment_count as u32).div_ceil(64);
    }
    for (i, count) in assurances.cores_assurances_counts().iter().enumerate() {
        let entry = core_stats.core_stats_entry_mut(i as CoreIndex);
        entry.assurers_count = *count as u16;
    }

    // Update service stats
    let mut service_stats = ServiceStats::default();
    for digest in guarantees
        .extract_work_reports()
        .into_iter()
        .flat_map(|wr| wr.digests)
    {
        let entry = service_stats.service_stats_entry_mut(digest.service_id);
        entry.accumulate_refine_stats(&digest.refine_stats);
    }
    for preimage in &preimages.items {
        let entry = service_stats.service_stats_entry_mut(preimage.service_id);
        entry.add_preimage_load(preimage)
    }
    for (service_id, stats_entry) in accumulate_stats.iter() {
        let entry = service_stats.service_stats_entry_mut(*service_id);
        entry.accumulate_gas_used += stats_entry.gas_used;
        entry.accumulate_reports_count += stats_entry.reports_count;
    }
    for (service_id, stats_entry) in on_transfer_stats.iter() {
        let entry = service_stats.service_stats_entry_mut(*service_id);
        entry.on_transfer_transfers_count += stats_entry.transfers_count;
        entry.on_transfer_gas_used += stats_entry.gas_used;
    }

    state_manager
        .with_mut_onchain_statistics(StateMut::Update, |stats| stats.core_stats = core_stats)
        .await?;

    Ok(())
}
