use crate::safrole::asn_types::SafroleErrorCode;
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> SafroleErrorCode {
    match e {
        TransitionError::InvalidTimeslot { .. } => SafroleErrorCode::bad_slot,
        TransitionError::ExtrinsicValidationError(TicketSubmissionClosed(_)) => {
            SafroleErrorCode::unexpected_ticket
        }
        TransitionError::ExtrinsicValidationError(TicketsNotSorted) => {
            SafroleErrorCode::bad_ticket_order
        }
        TransitionError::ExtrinsicValidationError(InvalidTicketProof(_)) => {
            SafroleErrorCode::bad_ticket_proof
        }
        TransitionError::ExtrinsicValidationError(InvalidTicketAttemptNumber(_)) => {
            SafroleErrorCode::bad_ticket_attempt
        }
        TransitionError::ExtrinsicValidationError(DuplicateTicket) => {
            SafroleErrorCode::duplicate_ticket
        }
        _ => SafroleErrorCode::reserved,
    }
}
