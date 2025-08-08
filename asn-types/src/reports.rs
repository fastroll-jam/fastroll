use crate::common::*;
use fr_common::{Balance, ServiceId, TimeslotIndex};

use fr_block::types::extrinsics::guarantees::GuaranteesXt;
use fr_common::workloads::ReportedWorkPackage;
use fr_crypto::types::Ed25519PubKey;
use fr_state::types::{AccountMetadata, Timeslot};
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

/// Subset of the `δ` relevant to the reports STF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccount {
    service: AsnServiceInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccountsMapEntry {
    pub id: AsnServiceId,
    pub data: AsnAccount,
}

impl From<AccountsMapEntry> for AsnAccountsMapEntry {
    fn from(value: AccountsMapEntry) -> Self {
        let info = AsnServiceInfo {
            code_hash: value.metadata.code_hash,
            balance: value.metadata.balance,
            min_item_gas: value.metadata.gas_limit_accumulate,
            min_memo_gas: value.metadata.gas_limit_on_transfer,
            bytes: value.metadata.octets_footprint,
            items: value.metadata.items_footprint,
        };

        Self {
            id: value.service_id,
            data: AsnAccount { service: info },
        }
    }
}

impl From<AsnAccountsMapEntry> for AccountsMapEntry {
    fn from(value: AsnAccountsMapEntry) -> Self {
        Self {
            service_id: value.id,
            metadata: AccountMetadata {
                code_hash: value.data.service.code_hash,
                balance: value.data.service.balance,
                gas_limit_accumulate: value.data.service.min_item_gas,
                gas_limit_on_transfer: value.data.service.min_memo_gas,
                items_footprint: value.data.service.items,
                octets_footprint: value.data.service.bytes,
                // FIXME: test vectors should be aligned with GP v0.6.7
                gratis_storage_offset: Balance::default(),
                created_at: TimeslotIndex::default(),
                last_accumulate_at: TimeslotIndex::default(),
                parent_service_id: ServiceId::default(),
            },
        }
    }
}

pub type AsnServices = Vec<AsnAccountsMapEntry>;

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
                .into_iter()
                .map(|reported| AsnReportedPackage {
                    work_package_hash: AsnOpaqueHash::from(reported.work_package_hash),
                    segment_tree_root: AsnOpaqueHash::from(reported.segment_root),
                })
                .collect(),
            reporters: output.reporters,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(OutputData),
    err(ReportsErrorCode),
}
