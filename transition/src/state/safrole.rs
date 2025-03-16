use crate::error::TransitionError;
use rjam_block::types::extrinsics::tickets::TicketsXt;
use rjam_common::{ticket::Ticket, EPOCH_LENGTH, TICKET_CONTEST_DURATION};
use rjam_crypto::{entropy_hash_ring_vrf, generate_ring_root};
use rjam_extrinsics::validation::{error::XtError, tickets::TicketsXtValidator};
use rjam_state::{
    cache::StateMut,
    manager::StateManager,
    types::{
        generate_fallback_keys, outside_in_vec, ActiveSet, EpochEntropy, SafroleState,
        SlotSealerType, TicketAccumulator, Timeslot, ValidatorSet,
    },
};
use std::sync::Arc;

/// State transition function of `SafroleState`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `γ_k`: Sets the pending set to the prior staging set.
/// * `γ_z`: Sets the ring root to the one generated from the current pending set.
/// * `γ_s`: Updates the slot-sealer series:
///     - In regular (ticket) mode: Applies the outside-in sequencer function to the prior ticket accumulator.
///     - In fallback mode: Generates a new fallback key sequence influenced by the current `η_2`.
/// * `γ_a`: Resets the ticket accumulator.
///
/// ## Per-block transitions
/// * `γ_k`: None.
/// * `γ_z`: None.
/// * `γ_s`: None.
/// * `γ_a`: Accumulates new tickets.
pub async fn transition_safrole(
    state_manager: Arc<StateManager>,
    prior_timeslot: &Timeslot,
    epoch_progressed: bool,
    tickets_xt: &TicketsXt,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        handle_new_epoch_transition(state_manager.clone(), prior_timeslot).await?;
    }

    // Ticket accumulator transition
    handle_ticket_accumulation(state_manager, tickets_xt).await?;

    Ok(())
}

async fn handle_new_epoch_transition(
    state_manager: Arc<StateManager>,
    prior_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let current_punish_set = state_manager.get_disputes().await?.punish_set;
    let mut prior_staging_set = state_manager.get_staging_set_clean().await?;

    // Remove punished validators from the staging set (iota).
    prior_staging_set.nullify_punished_validators(&current_punish_set);

    // Note: prior_staging_set is equivalent to current_pending_set
    let current_ring_root = generate_ring_root(&prior_staging_set)?;
    let current_active_set = state_manager.get_active_set().await?;
    let current_entropy = state_manager.get_epoch_entropy().await?;

    state_manager
        .with_mut_safrole(StateMut::Update, |safrole| {
            // pending set transition (γ_k)
            safrole.pending_set = prior_staging_set.0;

            // ring root transition (γ_z)
            safrole.ring_root = current_ring_root;

            // slot-sealer series transition (γ_s)
            update_slot_sealers(
                safrole,
                prior_timeslot,
                &current_active_set,
                &current_entropy,
            );

            // reset ticket accumulator (γ_a)
            safrole.ticket_accumulator = TicketAccumulator::new();
        })
        .await?;

    Ok(())
}

fn update_slot_sealers(
    safrole: &mut SafroleState,
    prior_timeslot: &Timeslot,
    current_active_set: &ActiveSet,
    current_entropy: &EpochEntropy,
) {
    // Fallback mode triggers when the slot phase hasn't reached the ticket submission deadline
    // or the ticket accumulator is not yet full.
    let is_fallback = (prior_timeslot.slot_phase() as usize) < TICKET_CONTEST_DURATION
        || !safrole.ticket_accumulator.is_full();

    if is_fallback {
        safrole.slot_sealers = SlotSealerType::BandersnatchPubKeys(Box::new(
            generate_fallback_keys(current_active_set, current_entropy.second_history()).unwrap(),
        ));
    } else {
        let ticket_accumulator_outside_in: [Ticket; EPOCH_LENGTH] =
            outside_in_vec(safrole.ticket_accumulator.as_vec())
                .try_into()
                .unwrap();
        safrole.slot_sealers = SlotSealerType::Tickets(Box::new(ticket_accumulator_outside_in));
    }
}

async fn handle_ticket_accumulation(
    state_manager: Arc<StateManager>,
    tickets_xt: &TicketsXt,
) -> Result<(), TransitionError> {
    if tickets_xt.is_empty() {
        return Ok(());
    }

    // Check if the current timeslot is within the ticket submission period.
    let current_slot_phase = state_manager.get_timeslot().await?.slot_phase();
    if current_slot_phase as usize >= TICKET_CONTEST_DURATION {
        return Err(TransitionError::XtValidationError(
            XtError::TicketSubmissionClosed(current_slot_phase),
        ));
    }

    // Validate ticket extrinsic data.
    let ticket_validator = TicketsXtValidator::new(&state_manager);
    ticket_validator.validate(tickets_xt).await?;

    // Construct new tickets from ticket extrinsics.
    let new_tickets = ticket_xt_to_new_tickets(tickets_xt);

    // Check if the ticket accumulator contains the new ticket entry.
    // If not, accumulate the new ticket entry into the accumulator.
    let mut curr_ticket_accumulator = state_manager.get_safrole_clean().await?.ticket_accumulator;
    for ticket in new_tickets {
        if curr_ticket_accumulator.contains(&ticket) {
            return Err(TransitionError::XtValidationError(XtError::DuplicateTicket));
        }
        curr_ticket_accumulator.add(ticket);
    }

    state_manager
        .with_mut_safrole(StateMut::Update, |safrole| {
            safrole.ticket_accumulator = curr_ticket_accumulator;
        })
        .await?;

    Ok(())
}

pub(crate) fn ticket_xt_to_new_tickets(tickets_xt: &TicketsXt) -> Vec<Ticket> {
    tickets_xt
        .iter()
        .map(|ticket| Ticket {
            id: entropy_hash_ring_vrf(&ticket.ticket_proof),
            attempt: ticket.entry_index,
        })
        .collect()
}
