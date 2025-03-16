use crate::validation::error::{XtValidationError, XtValidationError::*};
use rjam_common::{
    Hash32, MAX_TICKETS_PER_EXTRINSIC, TICKETS_PER_VALIDATOR, TICKET_CONTEST_DURATION, X_T,
};
use rjam_crypto::{validator_set_to_bandersnatch_ring, Verifier};
use rjam_state::StateManager;
use rjam_types::extrinsics::tickets::{TicketsXt, TicketsXtEntry};

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
///   submission deadline slot index, `TICKET_SUBMISSION_DEADLINE_SLOT`.
/// - Within the submission deadline, length of the extrinsic must not exceed `MAX_TICKETS_PER_EXTRINSIC`.
///
/// ## Entry Validation
/// - `ticket_proof`
///   - Each entry's `ticket_proof` must be a valid Bandersnatch RingVRF proof, using the `ring_root`
///     retrieved from the `SafroleState` and a context that includes the secondary history component
///     of the current entropy state and the ticket attempt identifier.
pub struct TicketsXtValidator<'a> {
    state_manger: &'a StateManager,
}

impl<'a> TicketsXtValidator<'a> {
    pub fn new(state_manger: &'a StateManager) -> Self {
        Self { state_manger }
    }

    /// Validates the entire `TicketsXt`.
    pub async fn validate(&self, extrinsic: &TicketsXt) -> Result<(), XtValidationError> {
        // Check the slot phase
        let current_slot_phase = self.state_manger.get_timeslot().await?.slot_phase();
        if current_slot_phase >= TICKET_CONTEST_DURATION as u32 && !extrinsic.is_empty() {
            return Err(TicketSubmissionClosed(current_slot_phase));
        }

        if extrinsic.len() > MAX_TICKETS_PER_EXTRINSIC {
            return Err(TicketsEntryLimitExceeded(
                extrinsic.len(),
                MAX_TICKETS_PER_EXTRINSIC,
            ));
        }

        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(TicketsNotSorted);
        }

        let pending_set = self.state_manger.get_safrole().await?.pending_set;
        let entropy_2 = self
            .state_manger
            .get_epoch_entropy()
            .await?
            .second_history();
        let ring = validator_set_to_bandersnatch_ring(&pending_set)?;
        let verifier = Verifier::new(ring);

        // Validate each entry
        for entry in extrinsic.iter() {
            self.validate_entry(entry, &verifier, &entropy_2)?;
        }

        Ok(())
    }

    /// Validates each `TicketsXtEntry`.
    fn validate_entry(
        &self,
        entry: &TicketsXtEntry,
        verifier: &Verifier,
        entropy_2: &Hash32,
    ) -> Result<(), XtValidationError> {
        // Check if the ticket attempt number is correct
        if entry.entry_index > TICKETS_PER_VALIDATOR - 1 {
            return Err(InvalidTicketAttemptNumber(entry.entry_index));
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
        verifier: &Verifier,
        entropy_2: &Hash32,
    ) -> Result<(), XtValidationError> {
        let mut expected_vrf_input = Vec::with_capacity(X_T.len() + entropy_2.len() + 1);
        expected_vrf_input.extend_from_slice(X_T);
        expected_vrf_input.extend_from_slice(entropy_2.as_slice());
        expected_vrf_input.push(entry.entry_index);

        let aux_data = vec![]; // no aux data for ticket vrf signature
        verifier
            .ring_vrf_verify(&expected_vrf_input, &aux_data, &entry.ticket_proof[..])
            .map_err(|_| InvalidTicketProof(hex::encode(&entry.ticket_proof[..])))?;

        Ok(())
    }
}
