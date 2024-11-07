use crate::{
    asn_types::{ByteArray32, OpaqueHash, ValidatorData, ValidatorsData},
    safrole::asn_types::{CustomErrorCode, TicketBody, TicketsOrKeys},
};
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;
use rjam_types::state::{entropy::EntropyAccumulator, safrole::SafroleState};

pub fn safrole_state_to_gammas(
    safrole: &SafroleState,
) -> (ValidatorsData, Vec<TicketBody>, TicketsOrKeys, [u8; 144]) {
    let gamma_k = safrole.pending_set.clone().map(ValidatorData::from);
    let gamma_a = safrole
        .ticket_accumulator
        .clone()
        .into_vec()
        .into_iter()
        .map(|ticket| TicketBody {
            id: ByteArray32(ticket.id),
            attempt: ticket.attempt,
        })
        .collect();
    let gamma_s = safrole.slot_sealers.clone().into();
    let gamma_z = safrole.ring_root.into();
    (gamma_k, gamma_a, gamma_s, gamma_z)
}

pub fn entropy_accumulator_to_eta(entropy_accumulator: &EntropyAccumulator) -> [OpaqueHash; 4] {
    entropy_accumulator.0.map(ByteArray32)
}

/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> CustomErrorCode {
    match e {
        TransitionError::InvalidTimeslot { .. } => CustomErrorCode::bad_slot,
        TransitionError::ExtrinsicValidationError(TicketSubmissionClosed(_)) => {
            CustomErrorCode::unexpected_ticket
        }
        TransitionError::ExtrinsicValidationError(TicketsNotSorted) => {
            CustomErrorCode::bad_ticket_order
        }
        TransitionError::ExtrinsicValidationError(InvalidTicketProof(_)) => {
            CustomErrorCode::bad_ticket_proof
        }
        TransitionError::ExtrinsicValidationError(InvalidTicketAttemptNumber(_)) => {
            CustomErrorCode::bad_ticket_attempt
        }
        TransitionError::ExtrinsicValidationError(DuplicateTicket) => {
            CustomErrorCode::duplicate_ticket
        }
        _ => CustomErrorCode::reserved,
    }
}
