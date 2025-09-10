use crate::error::TransitionError;
use fr_block::types::{
    block::{EpochMarker, EpochMarkerValidatorKey, WinningTicketsMarker},
    extrinsics::tickets::TicketsXt,
};
use fr_common::{EntropyHash, TICKET_CONTEST_DURATION, VALIDATOR_COUNT};
use fr_crypto::types::ValidatorKeySet;
use fr_extrinsics::validation::{error::XtError, tickets::TicketsXtValidator};
use fr_limited_vec::FixedVec;
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{
        generate_fallback_keys, outside_in_vec, ActiveSet, EpochTickets, SafroleHeaderMarkers,
        SafroleState, SlotSealers, TicketAccumulator, Timeslot, ValidatorSet,
    },
};
use std::sync::Arc;
use tracing::instrument;

/// State transition function of `SafroleState`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `γ_P`: Sets the pending set to the prior staging set.
/// * `γ_Z`: Sets the ring root to the one generated from the current pending set.
/// * `γ_S`: Updates the slot-sealer series:
///     - In regular (ticket) mode: Applies the outside-in sequencer function to the prior ticket accumulator.
///     - In fallback mode: Generates a new fallback key sequence influenced by the current `η_2`.
/// * `γ_A`: Resets the ticket accumulator.
///
/// ## Per-block transitions
/// * `γ_P`: None.
/// * `γ_Z`: None.
/// * `γ_S`: None.
/// * `γ_A`: Accumulates new tickets.
pub async fn transition_safrole(
    state_manager: Arc<StateManager>,
    prior_timeslot: &Timeslot,
    curr_timeslot: &Timeslot,
    epoch_progressed: bool,
    tickets_xt: &TicketsXt,
) -> Result<(), TransitionError> {
    tracing::info!("Safrole: new_epoch: {epoch_progressed}");
    if epoch_progressed {
        handle_new_epoch_transition(state_manager.clone(), prior_timeslot, curr_timeslot).await?;
    }

    // Ticket accumulator transition
    handle_ticket_accumulation(state_manager, tickets_xt).await?;

    Ok(())
}

async fn handle_new_epoch_transition(
    state_manager: Arc<StateManager>,
    prior_timeslot: &Timeslot,
    curr_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let current_punish_set = state_manager.get_disputes().await?.punish_set;
    let mut prior_staging_set = state_manager.get_staging_set_clean().await?;

    // Remove punished validators from the staging set (iota).
    prior_staging_set.nullify_punished_validators(&current_punish_set);

    let (_verifier, curr_ring_root) = state_manager
        .get_or_generate_ring_verifier_and_root(
            curr_timeslot.epoch(),
            curr_timeslot.slot(),
            &prior_staging_set,
        )
        .await?;

    let curr_active_set = state_manager.get_active_set().await?;
    let curr_entropy = state_manager.get_epoch_entropy().await?;

    state_manager
        .with_mut_safrole(
            StateMut::Update,
            |safrole| -> Result<(), StateManagerError> {
                // pending set transition (γ_P)
                safrole.pending_set = prior_staging_set.0;

                // ring root transition (γ_Z)
                safrole.ring_root = curr_ring_root;

                // slot-sealer series transition (γ_S)
                update_slot_sealers(
                    safrole,
                    prior_timeslot,
                    curr_timeslot,
                    &curr_active_set,
                    curr_entropy.second_history(),
                );

                // reset ticket accumulator (γ_A)
                safrole.ticket_accumulator = TicketAccumulator::new();
                Ok(())
            },
        )
        .await?;

    Ok(())
}
pub(crate) fn update_slot_sealers(
    safrole: &mut SafroleState,
    prior_timeslot: &Timeslot,
    curr_timeslot: &Timeslot,
    curr_active_set: &ActiveSet,
    curr_entropy_2: &EntropyHash,
) {
    // Fallback mode triggers under following conditions:
    // 1. One or more epochs are skipped (e′ > e + 1).
    // 2. The slot phase hasn't reached the ticket submission deadline.
    // 3. The ticket accumulator is not yet full.
    let is_fallback = curr_timeslot.epoch() > prior_timeslot.epoch() + 1
        || (prior_timeslot.slot_phase() as usize) < TICKET_CONTEST_DURATION
        || !safrole.ticket_accumulator.is_full();

    if is_fallback {
        tracing::trace!("New epoch.Prev slot sealers:\n{}", &safrole.slot_sealers);
        let fallback_keys = generate_fallback_keys(curr_active_set, curr_entropy_2)
            .expect("Failed to generate fallback keys");

        safrole.slot_sealers = SlotSealers::BandersnatchPubKeys(fallback_keys);
        tracing::trace!("Post slot sealers:\n{}", &safrole.slot_sealers);
    } else {
        let ticket_accumulator_outside_in =
            outside_in_vec(safrole.ticket_accumulator.clone().into_sorted_vec());
        let epoch_tickets = EpochTickets::try_from(ticket_accumulator_outside_in)
            .expect("ticket accumulator length exceeds EPOCH_LENGTH");
        safrole.slot_sealers = SlotSealers::Tickets(epoch_tickets);
    }
}

async fn handle_ticket_accumulation(
    state_manager: Arc<StateManager>,
    tickets_xt: &TicketsXt,
) -> Result<(), TransitionError> {
    tracing::info!("Safrole: {} ticket xts", tickets_xt.len());
    if tickets_xt.is_empty() {
        return Ok(());
    }

    // Check if the current timeslot is within the ticket submission period.
    let current_slot_phase = state_manager.get_timeslot().await?.slot_phase();
    if current_slot_phase as usize >= TICKET_CONTEST_DURATION {
        return Err(TransitionError::XtError(XtError::TicketSubmissionClosed(
            current_slot_phase,
        )));
    }

    // Validate ticket extrinsic data.
    let ticket_validator = TicketsXtValidator::new(state_manager.clone());
    let new_tickets = ticket_validator.validate(tickets_xt).await?;

    // Accumulate the new ticket entry into the accumulator (duplicate check done by `TicketsXtValidator`)
    state_manager
        .with_mut_safrole(
            StateMut::Update,
            |safrole| -> Result<(), StateManagerError> {
                safrole.ticket_accumulator.add_multiple(new_tickets);
                Ok(())
            },
        )
        .await?;

    Ok(())
}

fn extract_epoch_marker_keys(
    validator_set: &ValidatorKeySet,
) -> FixedVec<EpochMarkerValidatorKey, VALIDATOR_COUNT> {
    let mut result = Vec::with_capacity(VALIDATOR_COUNT);
    for key in validator_set.iter() {
        result.push(EpochMarkerValidatorKey {
            bandersnatch: key.bandersnatch.clone(),
            ed25519: key.ed25519.clone(),
        });
    }

    FixedVec::try_from(result).expect("size checked")
}

#[instrument(level = "debug", skip_all, name = "header_markers")]
pub async fn mark_safrole_header_markers(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<SafroleHeaderMarkers, TransitionError> {
    let prev_timeslot = state_manager.get_timeslot_clean().await?;
    let curr_timeslot = state_manager.get_timeslot().await?;
    let prev_safrole = state_manager.get_safrole_clean().await?;
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
        && prev_safrole.ticket_accumulator.is_full();

    let winning_tickets_marker = if needs_winning_tickets_marker {
        let marker_vec_outside_in =
            outside_in_vec(prev_safrole.ticket_accumulator.into_sorted_vec());
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
