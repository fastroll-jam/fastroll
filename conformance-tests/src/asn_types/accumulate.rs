use crate::asn_types::{
    common::{
        AccumulateRoot, AsnAccumulateHistory, AsnAccumulateQueue, AsnByteSequence, AsnEntropy,
        AsnPrivilegedServices, AsnServiceId, AsnServiceInfo, AsnTimeSlot, AsnWorkReport,
    },
    preimages::AsnPreimagesMapEntry,
};
use fr_common::{workloads::work_report::WorkReport, Hash32, Octets};
use fr_state::types::{AccountStorageEntry, Timeslot};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AccumulateErrorCode {
    reserved,
}

/// Wrapper of `AccountStorageEntry` including storage key.
pub struct StorageMapEntry {
    pub key: Octets,
    pub data: AccountStorageEntry,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnStorageMapEntry {
    pub key: AsnByteSequence,
    pub value: AsnByteSequence,
}

impl From<StorageMapEntry> for AsnStorageMapEntry {
    fn from(value: StorageMapEntry) -> Self {
        Self {
            key: AsnByteSequence(value.key.0),
            value: AsnByteSequence(value.data.value.0),
        }
    }
}

impl From<AsnStorageMapEntry> for StorageMapEntry {
    fn from(value: AsnStorageMapEntry) -> Self {
        Self {
            key: Octets::from_vec(value.key.0),
            data: AccountStorageEntry::new(Octets::from_vec(value.value.0)),
        }
    }
}

/// Subset of the `δ` relevant to the accumulate STF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccount {
    pub service: AsnServiceInfo,
    pub storage: Vec<AsnStorageMapEntry>,
    pub preimages: Vec<AsnPreimagesMapEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccountsMapEntry {
    pub id: AsnServiceId,
    pub data: AsnAccount,
}

pub type AsnServices = Vec<AsnAccountsMapEntry>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub slot: AsnTimeSlot,
    pub entropy: AsnEntropy,
    pub ready_queue: AsnAccumulateQueue,
    pub accumulated: AsnAccumulateHistory,
    pub privileges: AsnPrivilegedServices,
    pub accounts: AsnServices,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: AsnTimeSlot,
    pub reports: Vec<AsnWorkReport>,
}

pub struct JamInput {
    pub slot: Timeslot,
    pub reports: Vec<WorkReport>,
}

#[derive(Clone)]
pub struct JamTransitionOutput {
    pub accumulate_root: Hash32,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(AccumulateRoot),
    err,
}
