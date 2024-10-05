use crate::TransitionError;
use rjam_common::{
    sorted_limited_tickets::SortedLimitedTickets, Ticket, EPOCH_LENGTH,
    TICKET_SUBMISSION_DEADLINE_SLOT,
};
use rjam_crypto::{generate_ring_root, utils::entropy_hash_ring_vrf};
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::{
    extrinsics::tickets::TicketExtrinsicEntry,
    state::{
        entropy::EntropyAccumulator,
        safrole::{generate_fallback_keys, outside_in_vec, SafroleState, SlotSealerType},
        timeslot::Timeslot,
        validators::ActiveSet,
    },
};

/// State transition function of `SafroleState`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `gamma_k`: Sets the pending set to the prior staging set.
/// * `gamma_z`: Sets the ring root to the one generated from the current pending set.
/// * `gamma_s`: Updates the slot-sealer series:
///     - In ticket mode: Applies the outside-in sequencer function to the prior ticket accumulator.
///     - In fallback mode: Generates a new fallback key sequence influenced by the current `eta_2`.
/// * `gamma_a`: Resets the ticket accumulator.
///
/// ## Per-block transitions
/// * `gamma_k`: None.
/// * `gamma_z`: None.
/// * `gamma_s`: None.
/// * `gamma_a`: Accumulates new tickets.
pub fn transition_safrole(
    state_manager: &StateManager,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    let current_timeslot = state_manager.get_timeslot()?;

    if current_timeslot.is_new_epoch() {
        handle_new_epoch_transition(state_manager)?;
    }

    // Ticket accumulator transition
    handle_ticket_accumulation(state_manager, tickets)?;

    Ok(())
}

fn handle_new_epoch_transition(state_manager: &StateManager) -> Result<(), TransitionError> {
    let prior_timeslot = Timeslot::prior_slot(&state_manager.get_timeslot()?);
    let prior_staging_set = state_manager.get_staging_set()?; // TODO: nullify punished keys (`Phi` function)

    // Note: prior_staging_set is equivalent to current_pending_set
    let current_ring_root = generate_ring_root(&prior_staging_set.0)?;
    let current_active_set = state_manager.get_active_set()?;
    let current_entropy = state_manager.get_entropy_accumulator()?;

    state_manager.with_mut_safrole(StateWriteOp::Update, |safrole| {
        // pending set transition (gamma_k)
        safrole.pending_set = prior_staging_set.0;

        // ring root transition (gamma_z)
        safrole.ring_root = current_ring_root;

        // slot-sealer series transition (gamma_s)
        update_slot_sealers(
            safrole,
            &prior_timeslot,
            &current_active_set,
            &current_entropy,
        );

        // reset ticket accumulator (gamma_a)
        safrole.ticket_accumulator = SortedLimitedTickets::new();
    })?;

    Ok(())
}

fn update_slot_sealers(
    safrole: &mut SafroleState,
    prior_timeslot: &Timeslot,
    current_active_set: &ActiveSet,
    current_entropy: &EntropyAccumulator,
) {
    // Fallback mode triggers when the slot phase hasn't reached the ticket submission deadline
    // or the ticket accumulator is not yet full.
    let is_fallback = (prior_timeslot.slot_phase() as usize) < TICKET_SUBMISSION_DEADLINE_SLOT
        || !safrole.ticket_accumulator.is_full();

    if is_fallback {
        safrole.slot_sealers = SlotSealerType::BandersnatchPubKeys(Box::new(
            generate_fallback_keys(&current_active_set.0, current_entropy.second_history())
                .unwrap(),
        ));
    } else {
        let ticket_accumulator_outside_in: [Ticket; EPOCH_LENGTH] =
            outside_in_vec(safrole.ticket_accumulator.as_vec())
                .try_into()
                .unwrap();
        safrole.slot_sealers = SlotSealerType::Tickets(Box::new(ticket_accumulator_outside_in));
    }
}

fn handle_ticket_accumulation(
    state_manager: &StateManager,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    // Note: at the start of a new epoch, no ticket extrinsics should be submitted for accumulation.
    validate_ticket_order(tickets)?;

    // TODO: Verify the ring VRF proof of each ticket extrinsic (or verify on ticket reception)
    // Construct new tickets from ticket extrinsics
    let new_tickets = ticket_extrinsics_to_new_tickets(tickets);

    // Check if the ticket accumulator contains the new ticket entry
    // If not, accumulate the new ticket entry into the accumulator
    let mut curr_ticket_accumulator = SortedLimitedTickets::new();
    for ticket in new_tickets {
        if curr_ticket_accumulator.contains(&ticket) {
            return Err(TransitionError::DuplicateTicket);
        }
        curr_ticket_accumulator.add(ticket);
    }

    state_manager.with_mut_safrole(StateWriteOp::Update, |safrole| {
        safrole.ticket_accumulator = curr_ticket_accumulator;
    })?;

    Ok(())
}

/// Checks if the ticket extrinsics are ordered by ticket id.
fn validate_ticket_order(tickets: &[TicketExtrinsicEntry]) -> Result<(), TransitionError> {
    for window in tickets.windows(2) {
        if let [prev, curr] = window {
            if prev > curr {
                return Err(TransitionError::TicketsNotOrdered);
            }
        }
    }

    Ok(())
}

pub(crate) fn ticket_extrinsics_to_new_tickets(
    ticket_extrinsics: &[TicketExtrinsicEntry],
) -> Vec<Ticket> {
    ticket_extrinsics
        .iter()
        .map(|ticket| Ticket {
            id: entropy_hash_ring_vrf(&ticket.ticket_proof),
            attempt: ticket.entry_index,
        })
        .collect()
}
