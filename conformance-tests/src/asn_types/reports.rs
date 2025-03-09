use crate::asn_types::common::*;
use rjam_common::{Ed25519PubKey, ServiceId};

use rjam_types::{
    extrinsics::guarantees::GuaranteesXt,
    state::{AccountMetadata, ReportedWorkPackage, Timeslot},
};
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

/// Wrapper of `AccountMetadata` including service id.
pub struct AccountsMapEntry {
    pub service_id: ServiceId,
    pub metadata: AccountMetadata,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub avail_assignments: AsnAvailAssignments,
    pub curr_validators: AsnValidatorsData,
    pub prev_validators: AsnValidatorsData,
    pub entropy: AsnEntropyBuffer,
    pub offenders: Vec<AsnEd25519Key>,
    pub recent_blocks: AsnBlocksHistory,
    pub auth_pools: AsnAuthPools,
    pub accounts: AsnServices,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub guarantees: AsnGuaranteesXt,
    pub slot: AsnTimeSlot,
}

pub struct JamInput {
    pub extrinsic: GuaranteesXt,
    pub timeslot: Timeslot,
}

#[derive(Clone)]
pub struct JamTransitionOutput {
    pub reported: Vec<ReportedWorkPackage>,
    pub reporters: Vec<Ed25519PubKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnReportedPackage {
    pub work_package_hash: AsnWorkPackageHash,
    pub segment_tree_root: AsnOpaqueHash,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OutputData {
    pub reported: Vec<AsnReportedPackage>,
    pub reporters: Vec<AsnEd25519Key>,
}

impl From<JamTransitionOutput> for OutputData {
    fn from(output: JamTransitionOutput) -> Self {
        Self {
            reported: output
                .reported
                .iter()
                .map(|reported| AsnReportedPackage {
                    work_package_hash: AsnByteArray32(reported.work_package_hash.0),
                    segment_tree_root: AsnByteArray32(reported.segment_root.0),
                })
                .collect(),
            reporters: output
                .reporters
                .iter()
                .map(|key| AsnByteArray32(key.0))
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
