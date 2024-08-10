use crate::safrole::asn_types::{
    ByteArray32, CustomErrorCode, OpaqueHash, State, TicketBody, TicketsOrKeys, ValidatorData,
    ValidatorsData, U32, U8,
};
use rjam::{
    common::{
        sorted_limited_tickets::SortedLimitedTickets, BandersnatchPubKey, Ticket, EPOCH_LENGTH,
    },
    state::components::{
        entropy::EntropyAccumulator,
        safrole::{SafroleState, SlotSealerType},
        timeslot::Timeslot,
        validators::{
            ActiveValidatorSet, PastValidatorSet, StagingValidatorSet, ValidatorKey, ValidatorSet,
        },
    },
    transition::TransitionError,
};
use serde::{de, de::Visitor, Deserializer, Serializer};
use std::{error::Error, fmt};
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

//
// Helper Serde
//

// Helper deserializer to manage `0x` prefix
pub fn deserialize_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for HexVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {} bytes", N)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let v = v.strip_prefix("0x").unwrap_or(v);
            let bytes = hex::decode(v).map_err(E::custom)?;
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("Expected {} bytes", N)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

// Helper serializer to manage `0x` prefix
pub fn serialize_hex<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

//
// State Builder to facilitate conversion between ASN type representations and JAM implementation types
//

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
        self.gamma_k = Some(
            safrole
                .pending_validator_set
                .clone()
                .map(ValidatorData::from),
        );
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
        staging_set: &StagingValidatorSet,
        active_set: &ActiveValidatorSet,
        past_set: &PastValidatorSet,
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

impl State {
    pub fn into_safrole_state(&self) -> Result<SafroleState, AsnTypeError> {
        Ok(SafroleState {
            pending_validator_set: convert_validator_data(&self.gamma_k)?,
            ring_root: self.gamma_z.clone().try_into()?,
            slot_sealers: self.convert_slot_sealers()?,
            ticket_accumulator: SortedLimitedTickets::from_vec(
                self.gamma_a
                    .iter()
                    .map(|ticket_body| Ticket {
                        id: ticket_body.id.0,
                        attempt: ticket_body.attempt,
                    })
                    .collect(),
            ),
        })
    }
    // TODO: consider replacing this with trait implementation
    fn convert_slot_sealers(&self) -> Result<SlotSealerType, AsnTypeError> {
        match &self.gamma_s {
            TicketsOrKeys::tickets(ticket_bodies) => {
                let tickets: Box<[Ticket; EPOCH_LENGTH]> = ticket_bodies
                    .iter()
                    .map(|ticket_body| Ticket {
                        id: ticket_body.id.0,
                        attempt: ticket_body.attempt,
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        AsnTypeError::ConversionError(
                            "Failed to convert TicketsBodies to Tickets".to_string(),
                        )
                    })?;
                Ok(SlotSealerType::Tickets(tickets))
            }
            TicketsOrKeys::keys(epoch_keys) => {
                let keys: Box<[BandersnatchPubKey; EPOCH_LENGTH]> = epoch_keys
                    .iter()
                    .map(|key| key.0)
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        AsnTypeError::ConversionError(
                            "Failed to convert EpochKeys to BandersnatchPubKeys".to_string(),
                        )
                    })?;

                Ok(SlotSealerType::BandersnatchPubKeys(keys))
            }
        }
    }

    pub fn into_validator_sets(
        &self,
    ) -> Result<(StagingValidatorSet, ActiveValidatorSet, PastValidatorSet), AsnTypeError> {
        let staging_set = StagingValidatorSet(convert_validator_data(&self.iota)?);
        let active_set = ActiveValidatorSet(convert_validator_data(&self.kappa)?);
        let past_set = PastValidatorSet(convert_validator_data(&self.lambda)?);

        Ok((staging_set, active_set, past_set))
    }
    pub fn into_entropy_accumulator(&self) -> Result<EntropyAccumulator, AsnTypeError> {
        Ok(EntropyAccumulator(
            self.eta.clone().map(|entropy| entropy.0),
        ))
    }

    pub fn into_timeslot(&self) -> Result<Timeslot, AsnTypeError> {
        Ok(Timeslot(self.tau.clone().try_into()?))
    }
}

fn convert_validator_data(data: &ValidatorsData) -> Result<ValidatorSet, AsnTypeError> {
    data.iter()
        .map(|validator_data| {
            Ok::<ValidatorKey, AsnTypeError>(ValidatorKey {
                bandersnatch_key: validator_data.bandersnatch.0,
                ed25519_key: validator_data.ed25519.0,
                bls_key: validator_data.bls.0,
                metadata: validator_data.metadata,
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| AsnTypeError::ConversionError("Failed to convert ValidatorsData".to_string()))
}

//
// Conversion from JAM implementation Errors into test vectors' error code output
//

pub(crate) fn map_error_to_custom_code(error: Box<dyn Error>) -> CustomErrorCode {
    if let Some(transition_error) = error.downcast_ref::<TransitionError>() {
        match transition_error {
            TransitionError::InvalidTimeslot { .. } => CustomErrorCode::bad_slot,
            TransitionError::DuplicateTicket => CustomErrorCode::duplicate_ticket,
            TransitionError::TicketsNotOrdered => CustomErrorCode::bad_ticket_order,
            TransitionError::BadTicketProof => CustomErrorCode::bad_ticket_proof,
            _ => CustomErrorCode::reserved,
        }
    } else {
        CustomErrorCode::reserved
    }
}
