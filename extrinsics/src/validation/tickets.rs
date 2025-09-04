use crate::validation::error::XtError;
use fr_block::types::extrinsics::tickets::{TicketsXt, TicketsXtEntry};
use fr_common::{
    ticket::Ticket, ByteEncodable, Hash32, EPOCH_LENGTH, MAX_TICKETS_PER_EXTRINSIC,
    TICKETS_PER_VALIDATOR, TICKET_CONTEST_DURATION, X_T,
};
use fr_crypto::{error::CryptoError, traits::VrfSignature, vrf::bandersnatch_vrf::RingVrfVerifier};
use fr_state::manager::StateManager;
use std::{collections::HashSet, sync::Arc};
use tracing::debug_span;

#[tracing::instrument(level = "debug", skip_all, name = "xt_to_new_tickets")]
fn ticket_xt_to_new_tickets(tickets_xt: &TicketsXt) -> Result<Vec<Ticket>, CryptoError> {
    tickets_xt
        .iter()
        .map(|ticket| {
            Ok(Ticket {
                id: ticket.ticket_proof.output_hash()?,
                attempt: ticket.entry_index,
            })
        })
        .collect()
}

/// Validate contents of `TicketsXt` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Tickets entries ordered by their output hash of RingVRF proofs.
///
/// ## Length Limit
/// - The submission of tickets is limited to timeslots earlier than the ticket submission deadline
///   slot phase within an epoch. Thus, the current slot phase `m′` must be less than the ticket
///   submission deadline slot index, `TICKET_CONTEST_DURATION`.
/// - Within the submission deadline, length of the extrinsic must not exceed `MAX_TICKETS_PER_EXTRINSIC`.
///
/// ## Entry Validation
/// - `ticket_proof`
///   - Each entry's `ticket_proof` must be a valid Bandersnatch RingVRF proof, using the `ring_root`
///     retrieved from the `SafroleState` and a context that includes the secondary history component
///     of the current entropy state and the ticket attempt identifier.
pub struct TicketsXtValidator {
    state_manger: Arc<StateManager>,
}

impl TicketsXtValidator {
    pub fn new(state_manger: Arc<StateManager>) -> Self {
        Self { state_manger }
    }

    /// Validates the entire `TicketsXt`.
    #[tracing::instrument(level = "debug", skip_all, name = "validate_tickets_xt")]
    pub async fn validate(&self, extrinsic: &TicketsXt) -> Result<Vec<Ticket>, XtError> {
        if extrinsic.is_empty() {
            return Ok(vec![]);
        }

        // Check the slot phase
        let current_slot_phase = self.state_manger.get_timeslot().await?.slot_phase();
        if current_slot_phase >= TICKET_CONTEST_DURATION as u32 && !extrinsic.is_empty() {
            return Err(XtError::TicketSubmissionClosed(current_slot_phase));
        }

        if extrinsic.len() > MAX_TICKETS_PER_EXTRINSIC {
            return Err(XtError::TicketsEntryLimitExceeded(
                extrinsic.len(),
                MAX_TICKETS_PER_EXTRINSIC,
            ));
        }

        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(XtError::TicketsNotSorted);
        }

        // Construct new tickets from the tickets Xt.
        let new_tickets = ticket_xt_to_new_tickets(extrinsic)?;

        {
            let span = debug_span!("dup_check");
            let _e = span.enter();
            // Duplication check (within the Xt)
            let mut ticket_ids = HashSet::new();
            let no_duplicate_tickets = new_tickets
                .iter()
                .all(|entry| ticket_ids.insert(entry.id.clone()));
            if !no_duplicate_tickets {
                return Err(XtError::DuplicateTicket);
            }
        }

        let curr_ticket_accumulator = {
            let span = debug_span!("accumulator_dup_check");
            let _e = span.enter();
            // Duplication check (ticket accumulator)
            let curr_ticket_accumulator = self.state_manger.get_safrole().await?.ticket_accumulator;
            for ticket in &new_tickets {
                if curr_ticket_accumulator.contains(ticket) {
                    return Err(XtError::DuplicateTicket);
                }
            }
            curr_ticket_accumulator
        };

        {
            let span = debug_span!("check_useless_tickets");
            let _e = span.enter();
            // All new tickets should be useful; if any of them cannot be included in the posterior
            // ticket accumulator, the Xt is invalid.
            let accumulator_becomes_saturated =
                curr_ticket_accumulator.len() + new_tickets.len() > EPOCH_LENGTH;
            if accumulator_becomes_saturated {
                let tickets_in_accumulator_sorted = curr_ticket_accumulator.into_sorted_vec();

                // The number of tickets to be dropped after merging the new tickets
                let tickets_overflow =
                    tickets_in_accumulator_sorted.len() + new_tickets.len() - EPOCH_LENGTH;

                if tickets_overflow <= tickets_in_accumulator_sorted.len() {
                    let threshold_idx = tickets_in_accumulator_sorted.len() - tickets_overflow;
                    let threshold_ticket = &tickets_in_accumulator_sorted[threshold_idx];
                    if let Some(largest_new_ticket) = new_tickets.last() {
                        // There should be at least `tickets_overflow` tickets in the accumulator that have
                        // larger id than the largest new ticket.
                        if largest_new_ticket >= threshold_ticket {
                            return Err(XtError::UselessTickets);
                        }
                    }
                }
            }
        }

        // Get or generate `RingVrfVerifier` from the state manager cache.
        // In general this should be found from the cache since it is stored from the Safrole STF
        // on epoch progress.
        let verifier = self
            .state_manger
            .get_or_generate_ring_vrf_verifier()
            .await?;

        let epoch_entropy = self.state_manger.get_epoch_entropy().await?;
        let entropy_2 = epoch_entropy.second_history();

        // Validate each entry
        for entry in extrinsic.iter() {
            self.validate_entry(entry, &verifier, entropy_2)?;
        }

        Ok(new_tickets)
    }

    /// Validates each `TicketsXtEntry`.
    #[tracing::instrument(level = "debug", skip_all)]
    fn validate_entry(
        &self,
        entry: &TicketsXtEntry,
        verifier: &RingVrfVerifier,
        entropy_2: &Hash32,
    ) -> Result<(), XtError> {
        // Check if the ticket attempt number is correct
        if entry.entry_index > TICKETS_PER_VALIDATOR - 1 {
            return Err(XtError::InvalidTicketAttemptNumber(entry.entry_index));
        }

        Self::validate_ticket_proof(entry, verifier, entropy_2)?;

        Ok(())
    }

    /// Checks if the ticket extrinsics have valid VRF proofs.
    ///
    /// `entropy_2` refers to the current epoch entropy, after on-epoch-change transition.
    fn validate_ticket_proof(
        entry: &TicketsXtEntry,
        verifier: &RingVrfVerifier,
        entropy_2: &Hash32,
    ) -> Result<(), XtError> {
        let expected_context = [X_T, entropy_2.as_slice(), &[entry.entry_index]].concat();

        let message = vec![]; // no message for ticket vrf signature
        verifier
            .verify_ring_vrf(&expected_context, &message, &entry.ticket_proof)
            .map_err(|_| XtError::InvalidTicketProof(hex::encode(entry.ticket_proof.as_slice())))?;

        Ok(())
    }
}
