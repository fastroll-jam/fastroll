use fr_asn_types::safrole::SafroleErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> SafroleErrorCode {
    match e {
        TransitionError::InvalidTimeslot { .. } => SafroleErrorCode::bad_slot,
        TransitionError::XtError(XtError::TicketSubmissionClosed(_)) => {
            SafroleErrorCode::unexpected_ticket
        }
        TransitionError::XtError(XtError::TicketsNotSorted) => SafroleErrorCode::bad_ticket_order,
        TransitionError::XtError(XtError::InvalidTicketProof(_)) => {
            SafroleErrorCode::bad_ticket_proof
        }
        TransitionError::XtError(XtError::InvalidTicketAttemptNumber(_)) => {
            SafroleErrorCode::bad_ticket_attempt
        }
        TransitionError::XtError(XtError::DuplicateTicket) => SafroleErrorCode::duplicate_ticket,
        _ => SafroleErrorCode::reserved,
    }
}
