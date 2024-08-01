use crate::safrole::asn_types::{
    ByteArray32, OpaqueHash, State, TicketBody, TicketsOrKeys, ValidatorData, ValidatorsData, U32,
    U8,
};
use rjam::state::components::{
    entropy::EntropyAccumulator,
    safrole::SafroleState,
    timeslot::Timeslot,
    validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
};
use serde::{de, de::Visitor, Deserializer, Serializer};
use std::fmt;
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

// Conversion between ASN type representations and JAM implementation types
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
        self.tau = Some(timeslot.0.clone().try_into()?);
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

// impl State {
//     pub fn into_safrole_state(&self) -> Result<SafroleState, AsnTypeError> {
//         Ok(SafroleState {
//             pending_validator_set: self.gamma_k.clone().try_into()?,
//             ring_root: self.gamma_z.into(),
//             slot_sealers: self.gamma_s.clone().try_into()?,
//             ticket_accumulator: self.gamma_a.clone().try_into()?,
//         })
//     }
//
//     pub fn into_validator_sets(
//         &self,
//     ) -> Result<(StagingValidatorSet, ActiveValidatorSet, PastValidatorSet), AsnTypeError> {
//         let staging_set: StagingValidatorSet = self.iota.clone().try_into()?;
//         let active_set: ActiveValidatorSet = self.kappa.clone().try_into()?;
//         let past_set: PastValidatorSet = self.lambda.clone().try_into()?;
//
//         Ok((staging_set, active_set, past_set))
//     }
//
//     pub fn into_entropy_accumulator(&self) -> Result<EntropyAccumulator, AsnTypeError> {
//         self.eta.clone().try_into()
//         EntropyAccumulator { self.eta.clone() }
//     }
//
//     pub fn into_timeslot(&self) -> Result<Timeslot, AsnTypeError> {
//         self.tau.clone().try_into()
//     }
// }
