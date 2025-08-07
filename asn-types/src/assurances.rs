use crate::common::*;
use fr_block::types::extrinsics::assurances::AssurancesXt;
use fr_common::{workloads::work_report::WorkReport, BlockHeaderHash};
use fr_state::types::Timeslot;
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AssurancesErrorCode {
    bad_attestation_parent,
    bad_validator_index,
    core_not_engaged,
    bad_signature,
    not_sorted_or_unique_assurers,
    reserved,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub avail_assignments: AsnAvailAssignments,
    pub curr_validators: AsnValidatorsData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub assurances: AsnAssurancesXt,
    pub slot: AsnTimeSlot,
    pub parent: AsnHeaderHash,
}

pub struct JamInput {
    pub extrinsic: AssurancesXt,
    pub timeslot: Timeslot,
    pub parent_hash: BlockHeaderHash,
}

#[derive(Clone)]
pub struct JamTransitionOutput {
    pub removed_reports: Vec<WorkReport>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OutputData {
    /// Items removed from the pending reports, which now have become available.
    pub reported: Vec<AsnWorkReport>,
}

impl From<JamTransitionOutput> for OutputData {
    fn from(output: JamTransitionOutput) -> Self {
        Self {
            reported: output
                .removed_reports
                .into_iter()
                .map(AsnWorkReport::from)
                .collect(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(OutputData),
    err(AssurancesErrorCode),
}
