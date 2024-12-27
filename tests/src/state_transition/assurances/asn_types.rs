use crate::asn_types::{
    AsnAssurancesExtrinsic, AsnTimeSlot, AsnWorkReport, AvailAssignments, HeaderHash,
    ValidatorsData,
};
use rjam_common::Hash32;
use rjam_types::{
    common::workloads::WorkReport, extrinsics::assurances::AssurancesExtrinsic, state::Timeslot,
};
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
    pub avail_assignments: AvailAssignments,
    pub curr_validators: ValidatorsData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub assurances: AsnAssurancesExtrinsic,
    pub slot: AsnTimeSlot,
    pub parent: HeaderHash,
}

pub struct JamInput {
    pub extrinsic: AssurancesExtrinsic,
    pub timeslot: Timeslot,
    pub parent_hash: Hash32,
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
