use crate::error::TransitionError;
use rjam_block::types::extrinsics::Extrinsics;
use rjam_common::{get_validator_ed25519_key_by_index, ValidatorIndex};
use rjam_state::{cache::StateMut, manager::StateManager};
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
    handle_validator_stats_accumulation(state_manager, header_block_author_index, xts).await?;

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
            current_epoch_author_stats.preimages_count += xts.preimage_lookups.len() as u32;
            current_epoch_author_stats.preimage_data_octets_count +=
                xts.preimage_lookups.total_preimage_data_len() as u32;

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
