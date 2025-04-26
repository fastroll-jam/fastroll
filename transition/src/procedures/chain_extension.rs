use crate::{
    error::TransitionError,
    state::{
        entropy::transition_epoch_entropy,
        safrole::transition_safrole,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
use rjam_block::types::{
    block::{BlockHeader, EpochMarker, EpochMarkerValidatorKey, WinningTicketsMarker},
    extrinsics::tickets::TicketsXt,
};
use rjam_common::{TICKET_CONTEST_DURATION, VALIDATOR_COUNT};
use rjam_crypto::{types::ValidatorKeySet, vrf::bandersnatch_vrf::entropy_hash_ietf_vrf};
use rjam_state::{
    manager::StateManager,
    types::{outside_in_vec, Timeslot},
};
use std::sync::Arc;

pub struct SafroleHeaderMarkers {
    pub epoch_marker: Option<EpochMarker>,
    pub winning_tickets_marker: Option<WinningTicketsMarker>,
}

/// Performs the chain extension procedure by executing a series of state transitions in order.
///
/// 1. Timeslot: Updates the current timeslot based on the block header's timeslot index.
/// 2. Epoch Entropy: Updates the entropy based on the block header's VRF signature (H_v).
/// 3. Past Set: Updates the set of past validators.
/// 4. Active Set: Updates the set of currently active validators.
/// 5. Safrole: Updates Safrole state components, including ring root calculation and ticket processing.
pub async fn chain_extension_procedure(
    state_manager: Arc<StateManager>,
    header: BlockHeader,
    tickets: TicketsXt,
) -> Result<SafroleHeaderMarkers, TransitionError> {
    let prior_timeslot = state_manager.get_timeslot().await?;

    // Timeslot transition
    let header_timeslot_index = header.timeslot_index();
    transition_timeslot(state_manager.clone(), &Timeslot::new(header_timeslot_index)).await?;

    // Determine if the epoch has progressed
    let current_timeslot = state_manager.get_timeslot().await?;
    let epoch_progressed = prior_timeslot.epoch() < current_timeslot.epoch();

    // EpochEntropy transition
    let header_vrf_signature = &header.vrf_signature();
    transition_epoch_entropy(
        state_manager.clone(),
        epoch_progressed,
        entropy_hash_ietf_vrf(header_vrf_signature),
    )
    .await?;

    // PastSet transition
    transition_past_set(state_manager.clone(), epoch_progressed).await?;

    // ActiveSet transition
    transition_active_set(state_manager.clone(), epoch_progressed).await?;

    // Safrole transition
    transition_safrole(
        state_manager.clone(),
        &prior_timeslot,
        &current_timeslot,
        epoch_progressed,
        &tickets,
    )
    .await?;

    // Generates SafroleHeaderMarkers as output of the chain extension procedure.
    let markers = mark_safrole_header_markers(state_manager.clone(), epoch_progressed).await?;

    Ok(markers)
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
            entropy: prior_entropy.current(),
            tickets_entropy: prior_entropy.first_history(),
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
    let mut result = Box::new([EpochMarkerValidatorKey::default(); VALIDATOR_COUNT]);
    for (index, validator) in validator_set.iter().enumerate() {
        result[index] = EpochMarkerValidatorKey {
            bandersnatch_key: validator.bandersnatch_key,
            ed25519_key: validator.ed25519_key,
        }
    }
    result
}
