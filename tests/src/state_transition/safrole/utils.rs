use crate::{
    asn_types::{
        BandersnatchRingRoot, ByteArray32, TicketBody, TicketsOrKeys, ValidatorData, ValidatorsData,
    },
    safrole::asn_types::SafroleErrorCode,
};
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;
use rjam_types::state::*;

pub fn safrole_state_to_gammas(
    safrole: &SafroleState,
) -> (
    ValidatorsData,
    Vec<TicketBody>,
    TicketsOrKeys,
    BandersnatchRingRoot,
) {
    let gamma_k = safrole.pending_set.clone().map(ValidatorData::from);
    let gamma_a = safrole
        .ticket_accumulator
        .clone()
        .into_vec()
        .into_iter()
        .map(|ticket| TicketBody {
            id: ByteArray32(*ticket.id),
            attempt: ticket.attempt,
        })
        .collect();
    let gamma_s = safrole.slot_sealers.clone().into();
    let gamma_z = BandersnatchRingRoot(safrole.ring_root.0);
    (gamma_k, gamma_a, gamma_s, gamma_z)
}

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
