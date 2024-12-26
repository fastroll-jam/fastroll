use crate::asn_types::{
    AsnAuthPools, AsnBlocksHistory, AsnGuaranteesExtrinsic, AsnTimeSlot, AvailAssignments,
    ByteArray32, Ed25519Key, EntropyBuffer, OpaqueHash, Services, ValidatorsData, WorkPackageHash,
};
use rjam_common::{Ed25519PubKey, Hash32};
use rjam_types::{extrinsics::guarantees::GuaranteesExtrinsic, state::Timeslot};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ReportsErrorCode {
    bad_core_index,
    future_report_slot,
    report_epoch_before_last,
    insufficient_guarantees,
    out_of_order_guarantee,
    not_sorted_or_unique_guarantors,
    wrong_assignment,
    core_engaged,
    anchor_not_recent,
    bad_service_id,
    bad_code_hash,
    dependency_missing,
    duplicate_package,
    bad_state_root,
    bad_beefy_mmr_root,
    core_unauthorized,
    bad_validator_index,
    work_report_gas_too_high,
    service_item_gas_too_low,
    too_many_dependencies,
    segment_root_lookup_invalid,
    bad_signature,
    work_report_too_big,
    reserved,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub avail_assignments: AvailAssignments,
    pub curr_validators: ValidatorsData,
    pub prev_validators: ValidatorsData,
    pub entropy: EntropyBuffer,
    pub offenders: Vec<Ed25519Key>,
    pub recent_blocks: AsnBlocksHistory,
    pub auth_pools: AsnAuthPools,
    pub services: Services,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub guarantees: AsnGuaranteesExtrinsic,
    pub slot: AsnTimeSlot,
}

pub struct JamInput {
    pub extrinsic: GuaranteesExtrinsic,
    pub timeslot: Timeslot,
}

#[derive(Clone)]
pub struct JamTransitionOutput {
    pub reported: Vec<(Hash32, Hash32)>,
    pub reporters: Vec<Ed25519PubKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ReportedPackage {
    pub work_package_hash: WorkPackageHash,
    pub segment_tree_root: OpaqueHash,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OutputData {
    pub reported: Vec<ReportedPackage>,
    pub reporters: Vec<Ed25519Key>,
}

impl From<JamTransitionOutput> for OutputData {
    fn from(output: JamTransitionOutput) -> Self {
        Self {
            reported: output
                .reported
                .iter()
                .map(|(package_hash, segments_root)| ReportedPackage {
                    work_package_hash: ByteArray32(package_hash.0),
                    segment_tree_root: ByteArray32(segments_root.0),
                })
                .collect(),
            reporters: output
                .reporters
                .iter()
                .map(|key| ByteArray32(key.0))
                .collect(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(OutputData),
    err(ReportsErrorCode),
}
