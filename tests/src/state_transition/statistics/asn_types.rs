use crate::asn_types::{
    AsnExtrinsic, AsnStatistics, AsnTimeSlot, AsnValidatorIndex, ValidatorsData,
};
use rjam_common::ValidatorIndex;
use rjam_types::{extrinsics::Extrinsics, state::Timeslot};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Prior statistics
    pub pi: AsnStatistics,
    /// Prior timeslot
    pub tau: AsnTimeSlot,
    /// Posterior active validators
    pub kappa_prime: ValidatorsData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// Block timeslot
    pub slot: AsnTimeSlot,
    /// Block author
    pub author_index: AsnValidatorIndex,
    /// Extrinsic
    pub extrinsic: AsnExtrinsic,
}

pub struct JamInput {
    pub timeslot: Timeslot,
    pub author_index: ValidatorIndex,
    pub extrinsics: Extrinsics,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Output;
