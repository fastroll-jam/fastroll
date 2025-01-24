use crate::asn_types::safrole::SafroleErrorCode;
use rjam_extrinsics::validation::error::XtValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> SafroleErrorCode {
    match e {
        TransitionError::InvalidTimeslot { .. } => SafroleErrorCode::bad_slot,
        TransitionError::XtValidationError(TicketSubmissionClosed(_)) => {
            SafroleErrorCode::unexpected_ticket
        }
        TransitionError::XtValidationError(TicketsNotSorted) => SafroleErrorCode::bad_ticket_order,
        TransitionError::XtValidationError(InvalidTicketProof(_)) => {
            SafroleErrorCode::bad_ticket_proof
        }
        TransitionError::XtValidationError(InvalidTicketAttemptNumber(_)) => {
            SafroleErrorCode::bad_ticket_attempt
        }
        TransitionError::XtValidationError(DuplicateTicket) => SafroleErrorCode::duplicate_ticket,
        _ => SafroleErrorCode::reserved,
    }
}
