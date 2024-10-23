use crate::error::TransitionError;
use rjam_common::{
    sorted_limited_tickets::SortedLimitedTickets, Hash32, Ticket, ValidatorSet, EPOCH_LENGTH,
    TICKET_SUBMISSION_DEADLINE_SLOT, X_T,
};
use rjam_crypto::{
    generate_ring_root, utils::entropy_hash_ring_vrf, validator_set_to_bandersnatch_ring,
    vrf::Verifier,
};
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
    prior_timeslot: &Timeslot,
    epoch_progressed: bool,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    if epoch_progressed {
        handle_new_epoch_transition(state_manager, prior_timeslot)?;
    }

    // Ticket accumulator transition
    handle_ticket_accumulation(state_manager, tickets)?;

    Ok(())
}

fn handle_new_epoch_transition(
    state_manager: &StateManager,
    prior_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let current_punish_set = state_manager.get_disputes()?.punish_set;
    let mut prior_staging_set = state_manager.get_staging_set()?;

    // Remove punished validators from the staging set (iota).
    prior_staging_set.nullify_punished_validators(&current_punish_set);

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
    if tickets.is_empty() {
        return Ok(());
    }

    // Check if the current timeslot is within the ticket submission period.
    let current_slot_phase = state_manager.get_timeslot()?.slot_phase();
    if current_slot_phase as usize >= TICKET_SUBMISSION_DEADLINE_SLOT {
        return Err(TransitionError::TicketSubmissionClosed);
    }

    // Validate ticket extrinsic data.
    validate_tickets(state_manager, tickets)?;

    // Construct new tickets from ticket extrinsics.
    let new_tickets = ticket_extrinsics_to_new_tickets(tickets);

    // Check if the ticket accumulator contains the new ticket entry.
    // If not, accumulate the new ticket entry into the accumulator.
    let mut curr_ticket_accumulator = state_manager.get_safrole()?.ticket_accumulator;
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

/// Validates submitted ticket extrinsics.
fn validate_tickets(
    state_manager: &StateManager,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    validate_tickets_order(tickets)?;
    validate_tickets_attempts(tickets)?;
    let pending_set = state_manager.get_safrole()?.pending_set;
    let entropy_2 = state_manager.get_entropy_accumulator()?.second_history();
    validate_tickets_proofs(tickets, &pending_set, entropy_2)?;
    Ok(())
}

/// Checks if the ticket extrinsics are ordered by ticket id.
fn validate_tickets_order(tickets: &[TicketExtrinsicEntry]) -> Result<(), TransitionError> {
    for window in tickets.windows(2) {
        if let [prev, curr] = window {
            if prev > curr {
                return Err(TransitionError::TicketsNotOrdered);
            }
        }
    }

    Ok(())
}

/// Checks if the ticket extrinsics have valid VRF proofs.
///
/// The entropy_2 is the second history of the entropy accumulator, assuming that the Safrole state
/// transition happens after the entropy transition.
fn validate_tickets_proofs(
    tickets: &[TicketExtrinsicEntry],
    pending_set: &ValidatorSet,
    entropy_2: Hash32,
) -> Result<(), TransitionError> {
    let ring = validator_set_to_bandersnatch_ring(pending_set)?;
    let verifier = Verifier::new(ring);
    for ticket in tickets {
        let mut expected_vrf_input = vec![];
        expected_vrf_input.extend_from_slice(X_T.as_bytes());
        expected_vrf_input.extend_from_slice(&entropy_2);
        expected_vrf_input.push(ticket.entry_index);

        let aux_data = vec![]; // no aux data for ticket vrf signature
        let _ = verifier
            .ring_vrf_verify(&expected_vrf_input, &aux_data, &ticket.ticket_proof[..])
            .map_err(|_e| TransitionError::BadTicketProof)?;
    }
    Ok(())
}

/// Checks if the ticket extrinsics have valid attempt numbers (0 or 1).
fn validate_tickets_attempts(tickets: &[TicketExtrinsicEntry]) -> Result<(), TransitionError> {
    for ticket in tickets {
        if ticket.entry_index > 1 {
            return Err(TransitionError::BadTicketAttemptNumber);
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
