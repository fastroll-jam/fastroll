use crate::asn_types::common::*;
use fr_block::types::extrinsics::Extrinsics;
use fr_common::ValidatorIndex;
use fr_state::types::Timeslot;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Current epoch validators statistics
    pub vals_curr_stats: AsnActivityRecords,
    /// Last epoch validators statistics
    pub vals_last_stats: AsnActivityRecords,
    /// Prior timeslot
    pub slot: AsnTimeSlot,
    /// Posterior active validators
    pub curr_validators: AsnValidatorsData,
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
