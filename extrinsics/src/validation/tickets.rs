use crate::validation::error::ExtrinsicValidationError;
use rjam_common::{MAX_TICKETS_PER_EXTRINSIC, TICKET_SUBMISSION_DEADLINE_SLOT};
use rjam_state::StateManager;
use rjam_types::extrinsics::tickets::TicketsExtrinsic;

/// Validate contents of `TicketsExtrinsic` type.
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
///   - Note: currently this validation process is part of the Safrole state transition function,
///   - TODO: Consider moving that logic to this struct
pub struct TicketsExtrinsicValidator<'a> {
    state_manger: &'a StateManager,
}

impl<'a> TicketsExtrinsicValidator<'a> {
    pub fn new(state_manger: &'a StateManager) -> Self {
        Self { state_manger }
    }

    /// Validates the entire `TicketsExtrinsic`.
    pub fn validate(&self, extrinsic: &TicketsExtrinsic) -> Result<bool, ExtrinsicValidationError> {
        // Check the slot phase
        let current_slot_phase = self.state_manger.get_timeslot()?.slot_phase();
        if current_slot_phase >= TICKET_SUBMISSION_DEADLINE_SLOT as u32 && !extrinsic.is_empty() {
            return Ok(false);
        }

        if extrinsic.len() > MAX_TICKETS_PER_EXTRINSIC {
            return Ok(false);
        }

        Ok(true)
    }
}
