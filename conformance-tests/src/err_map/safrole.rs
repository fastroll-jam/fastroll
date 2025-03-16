use crate::asn_types::safrole::SafroleErrorCode;
use rjam_extrinsics::validation::error::XtError;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> SafroleErrorCode {
    match e {
        TransitionError::InvalidTimeslot { .. } => SafroleErrorCode::bad_slot,
        TransitionError::XtValidationError(XtError::TicketSubmissionClosed(_)) => {
            SafroleErrorCode::unexpected_ticket
        }
        TransitionError::XtValidationError(XtError::TicketsNotSorted) => {
            SafroleErrorCode::bad_ticket_order
        }
        TransitionError::XtValidationError(XtError::InvalidTicketProof(_)) => {
            SafroleErrorCode::bad_ticket_proof
        }
        TransitionError::XtValidationError(XtError::InvalidTicketAttemptNumber(_)) => {
            SafroleErrorCode::bad_ticket_attempt
        }
        TransitionError::XtValidationError(XtError::DuplicateTicket) => {
            SafroleErrorCode::duplicate_ticket
        }
        _ => SafroleErrorCode::reserved,
    }
}
