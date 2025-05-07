use crate::error::TransitionError;
use fr_block::types::block::{EpochMarker, EpochMarkerValidatorKey, WinningTicketsMarker};
use fr_common::{TICKET_CONTEST_DURATION, VALIDATOR_COUNT};
use fr_crypto::types::ValidatorKeySet;
use fr_state::{manager::StateManager, types::outside_in_vec};
use std::{array::from_fn, sync::Arc};

#[derive(Clone)]
pub struct SafroleHeaderMarkers {
    pub epoch_marker: Option<EpochMarker>,
    pub winning_tickets_marker: Option<WinningTicketsMarker>,
}

pub async fn mark_safrole_header_markers(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<SafroleHeaderMarkers, TransitionError> {
    let current_timeslot = state_manager.get_timeslot().await?;
    let current_safrole = state_manager.get_safrole().await?;

    let epoch_marker = if epoch_progressed {
        let prior_entropy = state_manager.get_epoch_entropy_clean().await?;
        let current_pending_set = current_safrole.pending_set;
        Some(EpochMarker {
            entropy: prior_entropy.current().clone(),
            tickets_entropy: prior_entropy.first_history().clone(),
            validators: extract_epoch_marker_keys(&current_pending_set),
        })
    } else {
        None
    };

    let needs_winning_tickets_marker = !epoch_progressed
        && current_timeslot.slot_phase() >= TICKET_CONTEST_DURATION as u32
        && current_safrole.ticket_accumulator.is_full();

    let winning_tickets_marker = if needs_winning_tickets_marker {
        let marker_vec_outside_in = outside_in_vec(current_safrole.ticket_accumulator.into_vec());
        Some(marker_vec_outside_in.try_into().unwrap())
    } else {
        None
    };

    Ok(SafroleHeaderMarkers {
        epoch_marker,
        winning_tickets_marker,
    })
}

fn extract_epoch_marker_keys(
    validator_set: &ValidatorKeySet,
) -> Box<[EpochMarkerValidatorKey; VALIDATOR_COUNT]> {
    let mut result = Box::new(from_fn(|_| EpochMarkerValidatorKey::default()));
    for (index, validator) in validator_set.iter().enumerate() {
        result[index] = EpochMarkerValidatorKey {
            bandersnatch_key: validator.bandersnatch_key.clone(),
            ed25519_key: validator.ed25519_key.clone(),
        }
    }
    result
}
