use crate::common::{AsnOpaqueHash, AsnPreimagesXt, AsnServiceId, AsnTimeSlot};
use fr_block::types::extrinsics::preimages::PreimagesXt;
use fr_common::{ByteSequence, LookupsKey, Octets, PreimagesKey};
use fr_state::types::{
    AccountLookupsEntry, AccountLookupsEntryTimeslots, AccountPreimagesEntry, Timeslot,
};
use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PreimagesErrorCode {
    preimage_unneeded,
    preimages_not_sorted_unique,
    reserved,
}

/// Wrapper of `AccountPreimagesEntry` including preimages key.
pub struct PreimagesMapEntry {
    pub key: PreimagesKey,
    pub data: AccountPreimagesEntry,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnPreimagesMapEntry {
    pub hash: AsnOpaqueHash,
    pub blob: ByteSequence,
}

impl From<PreimagesMapEntry> for AsnPreimagesMapEntry {
    fn from(value: PreimagesMapEntry) -> Self {
        Self {
            hash: value.key,
            blob: value.data.value,
        }
    }
}

impl From<AsnPreimagesMapEntry> for PreimagesMapEntry {
    fn from(value: AsnPreimagesMapEntry) -> Self {
        Self {
            key: value.hash,
            data: AccountPreimagesEntry::new(Octets::from(value.blob)),
        }
    }
}

/// Wrapper of `AccountLookupsEntry` including lookups key.
pub struct LookupMetaMapEntry {
    pub key: LookupsKey,
    pub data: AccountLookupsEntry,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnLookupMetaMapKey {
    pub hash: AsnOpaqueHash,
    pub length: u32,
}

impl From<LookupsKey> for AsnLookupMetaMapKey {
    fn from(value: LookupsKey) -> Self {
        Self {
            hash: value.0,
            length: value.1,
        }
    }
}

impl From<AsnLookupMetaMapKey> for LookupsKey {
    fn from(value: AsnLookupMetaMapKey) -> Self {
        (value.hash, value.length)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnLookupMetaMapEntry {
    pub key: AsnLookupMetaMapKey,
    pub value: Vec<AsnTimeSlot>,
}

impl From<LookupMetaMapEntry> for AsnLookupMetaMapEntry {
    fn from(value: LookupMetaMapEntry) -> Self {
        Self {
            key: value.key.into(),
            value: value.data.value.into_iter().map(|t| t.slot()).collect(),
        }
    }
}

impl From<AsnLookupMetaMapEntry> for LookupMetaMapEntry {
    fn from(value: AsnLookupMetaMapEntry) -> Self {
        let timeslots_vec: Vec<Timeslot> = value.value.into_iter().map(Timeslot::new).collect();
        Self {
            key: value.key.into(),
            data: AccountLookupsEntry::new(
                AccountLookupsEntryTimeslots::try_from(timeslots_vec).unwrap(),
            ),
        }
    }
}

/// Subset of the `δ` relevant to the preimages STF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccount {
    pub preimages: Vec<AsnPreimagesMapEntry>,
    pub lookup_meta: Vec<AsnLookupMetaMapEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAccountsMapEntry {
    pub id: AsnServiceId,
    pub data: AsnAccount,
}

pub type AsnServices = Vec<AsnAccountsMapEntry>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub accounts: AsnServices,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub preimages: AsnPreimagesXt,
    pub slot: AsnTimeSlot,
}

pub struct JamInput {
    pub extrinsic: PreimagesXt,
    pub slot: Timeslot,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok,
    err(PreimagesErrorCode),
}
