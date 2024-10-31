use crate::safrole::asn_types::{
    ByteArray32, CustomErrorCode, OpaqueHash, State, TicketBody, TicketsOrKeys, ValidatorData,
    ValidatorsData, U32, U8,
};
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;
use rjam_types::state::{
    entropy::EntropyAccumulator,
    safrole::SafroleState,
    timeslot::Timeslot,
    validators::{ActiveSet, PastSet, StagingSet},
};
use std::error::Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AsnTypeError {
    #[error("Safrole state conversion error: {0}")]
    ConversionError(String),
    #[error("Missing field for type conversion: {0}")]
    MissingField(&'static str),
    #[error("Type conversion infallible error")]
    InfallibleError(#[from] std::convert::Infallible),
}

/// State builder to facilitate conversion between ASN and RJAM types
#[derive(Default)]
pub struct StateBuilder {
    tau: Option<U32>,
    eta: Option<[OpaqueHash; 4]>,
    lambda: Option<ValidatorsData>,
    kappa: Option<ValidatorsData>,
    gamma_k: Option<ValidatorsData>,
    iota: Option<ValidatorsData>,
    gamma_a: Option<Vec<TicketBody>>,
    gamma_s: Option<TicketsOrKeys>,
    gamma_z: Option<[U8; 144]>,
}

impl StateBuilder {
    pub fn new() -> Self {
        StateBuilder::default()
    }

    // TODO: check if `clone`s are necessary
    pub fn from_safrole_state(mut self, safrole: &SafroleState) -> Result<Self, AsnTypeError> {
        self.gamma_k = Some(safrole.pending_set.clone().map(ValidatorData::from));
        self.gamma_a = Some(
            safrole
                .ticket_accumulator
                .clone()
                .into_vec()
                .into_iter()
                .map(|ticket| TicketBody {
                    id: ByteArray32(ticket.id),
                    attempt: ticket.attempt,
                })
                .collect(),
        );
        self.gamma_s = Some(safrole.slot_sealers.clone().try_into()?);
        self.gamma_z = Some(safrole.ring_root.into());
        Ok(self)
    }

    pub fn from_validator_sets(
        mut self,
        staging_set: &StagingSet,
        active_set: &ActiveSet,
        past_set: &PastSet,
    ) -> Result<Self, AsnTypeError> {
        self.lambda = Some(past_set.0.clone().map(ValidatorData::from));
        self.kappa = Some(active_set.0.clone().map(ValidatorData::from));
        self.iota = Some(staging_set.0.clone().map(ValidatorData::from));
        Ok(self)
    }

    pub fn from_entropy_accumulator(
        mut self,
        entropy_accumulator: &EntropyAccumulator,
    ) -> Result<Self, AsnTypeError> {
        self.eta = Some(entropy_accumulator.0.map(|hash| ByteArray32(hash)));
        Ok(self)
    }

    pub fn from_timeslot(mut self, timeslot: &Timeslot) -> Result<Self, AsnTypeError> {
        self.tau = Some(timeslot.slot().clone().try_into()?);
        Ok(self)
    }

    pub fn build(self) -> Result<State, AsnTypeError> {
        Ok(State {
            tau: self.tau.ok_or(AsnTypeError::MissingField("tau"))?,
            eta: self.eta.ok_or(AsnTypeError::MissingField("eta"))?,
            lambda: self.lambda.ok_or(AsnTypeError::MissingField("lambda"))?,
            kappa: self.kappa.ok_or(AsnTypeError::MissingField("kappa"))?,
            gamma_k: self.gamma_k.ok_or(AsnTypeError::MissingField("gamma_k"))?,
            iota: self.iota.ok_or(AsnTypeError::MissingField("iota"))?,
            gamma_a: self.gamma_a.ok_or(AsnTypeError::MissingField("gamma_a"))?,
            gamma_s: self.gamma_s.ok_or(AsnTypeError::MissingField("gamma_s"))?,
            gamma_z: self.gamma_z.ok_or(AsnTypeError::MissingField("gamma_z"))?,
        })
    }
}

/// Converts JAM implementation error types into test vector error code output
pub(crate) fn map_error_to_custom_code(error: Box<dyn Error>) -> CustomErrorCode {
    if let Some(transition_error) = error.downcast_ref::<TransitionError>() {
        match transition_error {
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
    } else {
        CustomErrorCode::reserved
    }
}
