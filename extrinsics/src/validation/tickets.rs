use crate::validation::error::XtError;
use rjam_block::types::extrinsics::tickets::{TicketsXt, TicketsXtEntry};
use rjam_common::{
    ByteEncodable, Hash32, MAX_TICKETS_PER_EXTRINSIC, TICKETS_PER_VALIDATOR,
    TICKET_CONTEST_DURATION, X_T,
};
use rjam_crypto::vrf::bandersnatch_vrf::RingVrfVerifier;
use rjam_state::manager::StateManager;
use std::sync::Arc;

/// Validate contents of `TicketsXt` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - No ordering rule applies.
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
    pub async fn validate(&self, extrinsic: &TicketsXt) -> Result<(), XtError> {
        // Check the slot phase
        let current_slot_phase = self.state_manger.get_timeslot().await?.slot_phase();
        if current_slot_phase >= TICKET_CONTEST_DURATION as u32 && !extrinsic.is_empty() {
            return Err(XtError::TicketSubmissionClosed(current_slot_phase));
        }

        // @GP(6.30::constraint::v0.6.5)
        if extrinsic.len() > MAX_TICKETS_PER_EXTRINSIC {
            return Err(XtError::TicketsEntryLimitExceeded(
                extrinsic.len(),
                MAX_TICKETS_PER_EXTRINSIC,
            ));
        }

        // @GP(6.32::constraint::v0.6.5)
        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(XtError::TicketsNotSorted);
        }

        let pending_set = self.state_manger.get_safrole().await?.pending_set;
        let epoch_entropy = self.state_manger.get_epoch_entropy().await?;
        let entropy_2 = epoch_entropy.second_history();
        let verifier = RingVrfVerifier::new(pending_set);

        // Validate each entry
        for entry in extrinsic.iter() {
            self.validate_entry(entry, &verifier, entropy_2)?;
        }

        Ok(())
    }

    /// Validates each `TicketsXtEntry`.
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
    /// The entropy_2 is the second history of the entropy accumulator, assuming that the Safrole state
    /// transition happens after the entropy transition.
    fn validate_ticket_proof(
        entry: &TicketsXtEntry,
        verifier: &RingVrfVerifier,
        entropy_2: &Hash32,
    ) -> Result<(), XtError> {
        let mut expected_context = Vec::with_capacity(X_T.len() + entropy_2.len() + 1);
        expected_context.extend_from_slice(X_T);
        expected_context.extend_from_slice(entropy_2.as_slice());
        expected_context.push(entry.entry_index);

        let message = vec![]; // no message for ticket vrf signature
        verifier
            .verify_ring_vrf(&expected_context, &message, &entry.ticket_proof)
            .map_err(|_| XtError::InvalidTicketProof(hex::encode(entry.ticket_proof.as_slice())))?;

        Ok(())
    }
}
