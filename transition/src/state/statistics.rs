use crate::error::TransitionError;
use rjam_common::ValidatorIndex;
use rjam_extrinsics::validation::error::XtValidationError::InvalidValidatorIndex;
use rjam_state::{StateManager, StateMut};
use rjam_types::{extrinsics::Extrinsics, state::validators::get_validator_ed25519_key_by_index};

/// State transition function of `ValidatorStats`
pub fn transition_validator_stats(
    state_manager: &StateManager,
    epoch_progressed: bool,
    header_block_author_index: ValidatorIndex,
    xts: &Extrinsics,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        handle_new_epoch_transition(state_manager)?;
    }

    // Validator stats accumulator transition (the first entry of the `ValidatorStats`)
    handle_stats_accumulation(state_manager, header_block_author_index, xts)?;

    Ok(())
}

fn handle_new_epoch_transition(state_manager: &StateManager) -> Result<(), TransitionError> {
    let prior_validator_stats = state_manager.get_validator_stats()?;
    let prior_current_epoch_stats = prior_validator_stats.current_epoch_stats();

    state_manager.with_mut_validator_stats(StateMut::Update, |stats| {
        stats.replace_previous_epoch_stats(prior_current_epoch_stats.clone());
        stats.clear_current_epoch_stats();
    })?;

    Ok(())
}

fn handle_stats_accumulation(
    state_manager: &StateManager,
    header_block_author_index: ValidatorIndex,
    xts: &Extrinsics,
) -> Result<(), TransitionError> {
    let current_active_set = state_manager.get_active_set()?;

    state_manager.with_mut_validator_stats(StateMut::Update, |stats| {
        let current_epoch_author_stats =
            stats.current_epoch_validator_stats_mut(header_block_author_index);

        current_epoch_author_stats.blocks_produced_count += 1;
        current_epoch_author_stats.tickets_count += xts.tickets.len() as u32;
        current_epoch_author_stats.preimages_count += xts.preimage_lookups.len() as u32;
        current_epoch_author_stats.preimage_data_octets_count +=
            xts.preimage_lookups.total_preimage_data_len() as u32;

        for (validator_index, validator_stats) in
            stats.current_epoch_stats_mut().iter_mut().enumerate()
        {
            let validator_index = validator_index as ValidatorIndex;
            let validator_ed25519_key =
                get_validator_ed25519_key_by_index(&current_active_set, validator_index)
                    .map_err(|_| TransitionError::XtValidationError(InvalidValidatorIndex))
                    .unwrap(); // TODO: proper validation error handling

            // Update `guarantees_count` if the current validator's Ed25519 public key is in reporters set.
            if xts
                .guarantees
                .extract_reporters(&current_active_set)
                .iter()
                .any(|reporter| reporter == &validator_ed25519_key)
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
    })?;

    Ok(())
}
