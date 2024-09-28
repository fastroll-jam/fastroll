use rjam_common::{Balance, Hash32, Octets, UnsignedGas};

#[derive(Clone)]
pub struct AccountInfo {
    pub code_hash: Hash32,                  // c
    pub balance: Balance,                   // b
    pub gas_limit_accumulate: UnsignedGas,  // g
    pub gas_limit_on_transfer: UnsignedGas, // m
}

#[derive(Clone)]
pub struct AccountMetadata {
    pub account_info: AccountInfo,
    storage_entry_count: usize,
    lookups_entry_count: usize,
    storage_octets_count: usize,
    lookups_octets_count: usize,
}

impl AccountMetadata {
    /// Returns the number of items in the service storages (i)
    pub fn get_item_counts_footprint(&self) -> usize {
        2 * self.lookups_entry_count + self.storage_entry_count
    }

    /// Returns the number of total octets used in the service storages (l)
    pub fn get_total_octets_footprint(&self) -> usize {
        self.lookups_octets_count + self.storage_octets_count
    }

    pub fn update_storage_footprint() {
        unimplemented!()
    }

    pub fn update_lookups_footprint() {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct AccountStorageEntry {
    key: Hash32, // constructed with the account address and the storage key
    value: Octets,
}

#[derive(Clone)]
pub struct AccountPreimagesEntry {
    key: Hash32, // constructed with the account address and the preimages dictionary key
    value: Octets,
}

#[derive(Clone)]
pub struct AccountLookupsEntry {
    key: Hash32,   // constructed with the account address and the lookup dictionary key
    value: Octets, // serialized timeslot list
}
