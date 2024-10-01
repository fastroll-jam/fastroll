use crate::state::timeslot::Timeslot;
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Balance, Hash32, Octets, UnsignedGas};

pub const B_S: Balance = 100; // The basic minimum balance which all services require
pub const B_I: Balance = 10; // The additional minimum balance required per item of elective service state
pub const B_L: Balance = 1; // The additional minimum balance required per octet of elective service state

#[derive(Clone, JamEncode, JamDecode)]
pub struct AccountInfo {
    pub code_hash: Hash32,                  // c
    pub balance: Balance,                   // b
    pub gas_limit_accumulate: UnsignedGas,  // g
    pub gas_limit_on_transfer: UnsignedGas, // m
}

#[derive(Clone, JamEncode, JamDecode)]
pub struct AccountMetadata {
    pub account_info: AccountInfo,
    /// The number of total octets used in the service storages (l)
    /// (lookups octets count) + (storage octets count)
    pub total_octets_footprint: u64,
    /// The number of items in the service storages (i)
    /// 2 * (lookups entry count) + (storage entry count)
    pub item_counts_footprint: u32,
}

impl AccountMetadata {
    pub fn update_storage_footprint() {
        unimplemented!()
    }

    pub fn update_lookups_footprint() {
        unimplemented!()
    }

    /// Get the account threshold balance (t)
    pub fn get_threshold_balance(&self) -> Balance {
        let i = self.item_counts_footprint as Balance;
        let l = self.total_octets_footprint as Balance;

        B_S + B_I * i + B_L * l
    }

    pub fn get_initial_threshold_balance() -> Balance {
        B_S
    }
}

// FIXME
#[derive(Clone)]
pub struct AccountStorageEntry {
    // pub key: Hash32, // constructed with the account address and the storage key
    pub value: Octets,
}

#[derive(Clone)]
pub struct AccountPreimagesEntry {
    // pub key: Hash32, // constructed with the account address and the preimages dictionary key
    pub value: Octets,
}

#[derive(Clone, JamEncode, JamDecode)]
pub struct AccountLookupsEntry {
    // pub key: Hash32, // constructed with the account address and the lookup dictionary key (h)
    // pub preimage_length: u32, // serialized preimage length (l)
    pub value: Vec<Timeslot>, // serialized timeslot list; length up to 3
}
