use crate::error::TransitionError;
use fr_block::types::block::{EpochMarker, EpochMarkerValidatorKey, WinningTicketsMarker};
use fr_common::{TICKET_CONTEST_DURATION, VALIDATOR_COUNT};
use fr_crypto::types::ValidatorKeySet;
use fr_limited_vec::FixedVec;
use fr_state::{
    manager::StateManager,
    types::{outside_in_vec, SafroleHeaderMarkers},
};
use std::sync::Arc;

pub async fn mark_safrole_header_markers(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<SafroleHeaderMarkers, TransitionError> {
    let prev_timeslot = state_manager.get_timeslot_clean().await?;
    let curr_timeslot = state_manager.get_timeslot().await?;
    let curr_safrole = state_manager.get_safrole().await?;

    let epoch_marker = if epoch_progressed {
        let prior_entropy = state_manager.get_epoch_entropy_clean().await?;
        let curr_pending_set = curr_safrole.pending_set;
        Some(EpochMarker {
            entropy: prior_entropy.current().clone(),
            tickets_entropy: prior_entropy.first_history().clone(),
            validators: extract_epoch_marker_keys(&curr_pending_set),
        })
    } else {
        None
    };

    let needs_winning_tickets_marker = !epoch_progressed
        && prev_timeslot.slot_phase() < TICKET_CONTEST_DURATION as u32
        && curr_timeslot.slot_phase() >= TICKET_CONTEST_DURATION as u32
        && curr_safrole.ticket_accumulator.is_full();

    let winning_tickets_marker = if needs_winning_tickets_marker {
        let marker_vec_outside_in = outside_in_vec(curr_safrole.ticket_accumulator.into_vec());
        let marker = WinningTicketsMarker::try_from(marker_vec_outside_in)?;
        Some(marker)
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
) -> FixedVec<EpochMarkerValidatorKey, VALIDATOR_COUNT> {
    let mut result = Vec::with_capacity(VALIDATOR_COUNT);
    for key in validator_set.iter() {
        result.push(EpochMarkerValidatorKey {
            bandersnatch_key: key.bandersnatch_key.clone(),
            ed25519_key: key.ed25519_key.clone(),
        });
    }

    FixedVec::try_from(result).expect("size checked")
}
