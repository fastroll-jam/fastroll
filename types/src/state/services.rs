use crate::{
    impl_account_state_component, impl_simple_state_component,
    state::timeslot::Timeslot,
    state_utils::{
        AccountStateComponent, SimpleStateComponent, StateComponent, StateEntryType,
        StateKeyConstant,
    },
};
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{Address, Balance, Hash32, Octets, UnsignedGas};
use std::collections::HashMap;

pub const B_S: Balance = 100; // The basic minimum balance which all services require
pub const B_I: Balance = 10; // The additional minimum balance required per item of elective service state
pub const B_L: Balance = 1; // The additional minimum balance required per octet of elective service state

#[derive(Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountInfo {
    pub code_hash: Hash32,                  // c
    pub balance: Balance,                   // b
    pub gas_limit_accumulate: UnsignedGas,  // g
    pub gas_limit_on_transfer: UnsignedGas, // m
}

#[derive(Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountMetadata {
    pub address: Address,
    pub account_info: AccountInfo,
    /// The number of entries of the account lookups dictionary
    pub lookups_items_count: u32,
    /// The number of entries of the account storage
    pub storage_items_count: u32,
    /// The number of total octets used by the account preimage lookup storage
    /// Note: this counts the preimage data octets, not the lookup timestamp octets.
    pub lookups_total_octets: u64,
    /// The number of total octets used by the account storage
    pub storage_total_octets: u64,
}
impl_account_state_component!(AccountMetadata, AccountMetadata);

impl AccountMetadata {
    pub fn new(account_info: AccountInfo) -> Self {
        Self {
            account_info,
            ..Default::default()
        }
    }

    /// The number of items in the service storages (i)
    ///
    /// 2 * `lookups_items_count` + `storage_items_count`
    pub fn item_counts_footprint(&self) -> u32 {
        2 * self.lookups_items_count + self.storage_items_count
    }

    /// The number of total octets used in the service storages (l)
    ///
    /// Sum({ 81 + preimage_data_len }) + Sum({ 32 + storage_data_len })
    pub fn total_octets_footprint(&self) -> u64 {
        81 * self.lookups_items_count as u64
            + self.lookups_total_octets
            + 32 * self.storage_items_count as u64
            + self.storage_total_octets
    }

    pub fn balance(&self) -> Balance {
        self.account_info.balance
    }

    /// Get the account threshold balance (t)
    pub fn threshold_balance(&self) -> Balance {
        let i = self.item_counts_footprint() as Balance;
        let l = self.total_octets_footprint();

        B_S + B_I * i + B_L * l
    }

    /// Calculates the state delta of the storage footprints caused by introducing the `new_entry`
    /// to the account storages.
    ///
    /// # Returns
    ///
    /// A tuple of (storage items count delta, storage octets count delta).
    pub fn calculate_storage_footprint_delta<T>(
        prev_entry: Option<&T>,
        new_entry: &T,
    ) -> Option<(i32, i128)>
    where
        T: StorageFootprint,
    {
        match (prev_entry, new_entry.is_empty()) {
            (Some(entry), true) => {
                // Case 1: Deleting the existing storage or lookups entry
                Some((-1, -(entry.storage_octets_usage() as i128)))
            }
            (Some(entry), false) => {
                // Case 2: Updating the existing storage or lookups entry
                Some((
                    0,
                    new_entry.storage_octets_usage() as i128 - entry.storage_octets_usage() as i128,
                ))
            }
            (None, true) => {
                // Case 3: Attempted to delete a storage or lookups entry that doesn't exist.
                None
            }
            (None, false) => {
                // Case 4: Adding a new storage or lookups entry
                Some((1, new_entry.storage_octets_usage() as i128))
            }
        }
    }

    /// Simulates mutating account storages to get the estimated threshold balance required after
    /// the mutation. Used to evaluate validity of such mutation in host functions that update the
    /// account storages.
    pub fn simulate_threshold_balance_after_mutation(
        &self,
        lookups_items_delta: i32,
        storage_items_delta: i32,
        lookups_octets_delta: i128,
        storage_octets_delta: i128,
    ) -> Balance {
        let mut simulated = self.clone();
        simulated.update_lookups_items_count(lookups_items_delta);
        simulated.update_storage_items_count(storage_items_delta);
        simulated.update_lookups_total_octets(lookups_octets_delta);
        simulated.update_storage_total_octets(storage_octets_delta);

        simulated.threshold_balance()
    }

    pub const fn get_initial_threshold_balance() -> Balance {
        B_S
    }

    pub fn update_lookups_items_count(&mut self, delta: i32) {
        self.lookups_items_count += delta as u32;
    }

    pub fn update_storage_items_count(&mut self, delta: i32) {
        self.storage_items_count += delta as u32;
    }

    pub fn update_lookups_total_octets(&mut self, delta: i128) {
        self.lookups_total_octets += delta as u64;
    }

    pub fn update_storage_total_octets(&mut self, delta: i128) {
        self.storage_total_octets += delta as u64;
    }

    /// Used by the PVM `host_info` execution.
    pub fn encode_for_info_hostcall(&self) -> Result<Vec<u8>, JamCodecError> {
        let mut buf = vec![];
        self.account_info.code_hash.encode_to(&mut buf)?; // c
        self.account_info.balance.encode_to(&mut buf)?; // b
        self.threshold_balance().encode_to(&mut buf)?; // t
        self.account_info.gas_limit_accumulate.encode_to(&mut buf)?; // g
        self.account_info
            .gas_limit_on_transfer
            .encode_to(&mut buf)?; // m
        self.total_octets_footprint().encode_to(&mut buf)?; // l
        self.item_counts_footprint().encode_to(&mut buf)?; // i

        Ok(buf)
    }
}

/// Represents storage entry types that are used for metering storage usage footprint.
pub trait StorageFootprint {
    fn storage_octets_usage(&self) -> usize;
    fn is_empty(&self) -> bool;
}

/// A marker trait for types that represent account state components used in PVM invocation contexts.
///
/// This is used to group types that are part of an account's state and are eligible for
/// manipulation or evaluation in a sandboxed PVM hostcall execution context.
pub trait PVMContextState {}
impl PVMContextState for AccountMetadata {}
impl PVMContextState for AccountStorageEntry {}
impl PVMContextState for AccountPreimagesEntry {}
impl PVMContextState for AccountLookupsEntry {}

#[derive(Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountStorageEntry {
    pub value: Octets,
}
impl_account_state_component!(AccountStorageEntry, AccountStorageEntry);

impl StorageFootprint for AccountStorageEntry {
    fn storage_octets_usage(&self) -> usize {
        self.value.len()
    }

    fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

#[derive(Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountPreimagesEntry {
    pub value: Octets,
}
impl_account_state_component!(AccountPreimagesEntry, AccountPreimagesEntry);

#[derive(Clone, Default, PartialEq, Eq)]
pub struct AccountLookupsEntry {
    pub value: Vec<Timeslot>, // serialized timeslot list; length up to 3
}
impl_account_state_component!(AccountLookupsEntry, AccountLookupsEntry);

impl JamEncode for AccountLookupsEntry {
    fn size_hint(&self) -> usize {
        self.value.len().size_hint() + 4 * self.value.len()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.value.len().encode_to(dest)?;
        for timeslot in &self.value {
            timeslot.encode_to_fixed(dest, 4)?;
        }
        Ok(())
    }
}

impl JamDecode for AccountLookupsEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let len = usize::decode(input)?;
        let mut timeslots = Vec::with_capacity(len);
        for _ in 0..len {
            let timeslot = Timeslot::decode_fixed(input, 4)?;
            timeslots.push(timeslot)
        }

        Ok(Self { value: timeslots })
    }
}

/// An extended type of `AccountLookupsEntry` that include additional metadata about the preimage
/// entry size in octets. This is useful for tracking storage usage and calculating threshold balance
/// of an account. This is NOT serialized as part of the global state.
pub struct AccountLookupsOctetsUsage {
    pub preimage_length: u32, // serialized preimage length (l)
    pub entry: AccountLookupsEntry,
}

impl StorageFootprint for AccountLookupsOctetsUsage {
    /// Note: Storage octets usage of lookups storage is counted by the preimage data size,
    /// not the size of the timeslots vector.
    fn storage_octets_usage(&self) -> usize {
        self.preimage_length as usize
    }

    fn is_empty(&self) -> bool {
        self.entry.value.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PrivilegedServices {
    pub manager_service: Address, // m; Alters state privileged services (`chi`).
    pub assign_service: Address,  // a; Alters auth queue (`phi`).
    pub designate_service: Address, // v; Alters staging validator set (`iota`).
    pub always_accumulate_services: HashMap<Address, UnsignedGas>, // g; Basic gas usage of always-accumulate services.
}
impl_simple_state_component!(PrivilegedServices, PrivilegedServices);
