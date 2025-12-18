use crate::{
    common::{
        AsnAccumulateHistory, AsnAccumulateQueue, AsnAccumulateRoot, AsnEntropy,
        AsnPrivilegedServices, AsnServiceId, AsnServiceInfo, AsnTimeSlot, AsnWorkReport,
    },
    preimages::{AsnLookupMetaMapEntry, AsnPreimagesMapEntry},
};
use fr_common::{
    workloads::work_report::WorkReport, AccumulateRoot, ByteSequence, Octets, StorageKey,
};
use fr_state::types::{AccountStorageEntry, Timeslot};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AccumulateErrorCode {
    reserved,
}

/// Wrapper of `AccountStorageEntry` including storage key.
pub struct StorageMapEntry {
    pub key: StorageKey,
    pub data: AccountStorageEntry,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnStorageMapEntry {
    pub key: ByteSequence,
    pub value: ByteSequence,
}

impl From<StorageMapEntry> for AsnStorageMapEntry {
    fn from(value: StorageMapEntry) -> Self {
        Self {
            key: ByteSequence(value.key.0),
            value: ByteSequence(value.data.value.0),
        }
    }
}

impl From<AsnStorageMapEntry> for StorageMapEntry {
    fn from(value: AsnStorageMapEntry) -> Self {
        Self {
            key: StorageKey::from_vec(value.key.0),
            data: AccountStorageEntry::new(Octets::from_vec(value.value.0)),
        }
    }
}

/// Subset of the `δ` relevant to the accumulate STF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccount {
    pub service: AsnServiceInfo,
    pub storage: Vec<AsnStorageMapEntry>,
    pub preimage_blobs: Vec<AsnPreimagesMapEntry>,
    pub preimage_requests: Vec<AsnLookupMetaMapEntry>,
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
    pub accumulate_root: AccumulateRoot,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(AsnAccumulateRoot),
    err,
}
