use crate::{
    impl_account_state_component, impl_simple_state_component,
    state_utils::{
        AccountStateComponent, SimpleStateComponent, StateComponent, StateEntryType,
        StateKeyConstant,
    },
    types::Timeslot,
};
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{
    Balance, Hash32, LookupsKey, Octets, ServiceId, UnsignedGas, MIN_BALANCE_PER_ITEM,
    MIN_BALANCE_PER_OCTET, MIN_BASIC_BALANCE,
};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

#[derive(Clone, Copy, Default)]
pub struct StorageUsageDelta {
    pub items_count_delta: i32,
    pub octets_delta: i64,
}

impl StorageUsageDelta {
    pub fn new(items_count_delta: i32, octets_delta: i64) -> Self {
        Self {
            items_count_delta,
            octets_delta,
        }
    }
}

pub struct AccountStorageUsageDelta {
    pub storage_delta: StorageUsageDelta,
    pub lookups_delta: StorageUsageDelta,
}

struct FootprintDelta {
    items_footprint_delta: i32,
    octets_footprint_delta: i64,
}

impl FootprintDelta {
    fn has_delta(&self) -> bool {
        self.items_footprint_delta != 0 || self.octets_footprint_delta != 0
    }
}

pub struct AccountFootprintDelta {
    storage_delta: FootprintDelta,
    lookups_delta: FootprintDelta,
}

impl From<AccountStorageUsageDelta> for AccountFootprintDelta {
    fn from(delta: AccountStorageUsageDelta) -> Self {
        Self {
            storage_delta: FootprintDelta {
                items_footprint_delta: delta.storage_delta.items_count_delta,
                octets_footprint_delta: 32 * delta.storage_delta.items_count_delta as i64
                    + delta.storage_delta.octets_delta,
            },
            lookups_delta: FootprintDelta {
                items_footprint_delta: 2 * delta.lookups_delta.items_count_delta,
                octets_footprint_delta: 81 * delta.lookups_delta.items_count_delta as i64
                    + delta.lookups_delta.octets_delta,
            },
        }
    }
}

impl AccountFootprintDelta {
    fn has_delta(&self) -> bool {
        self.storage_delta.has_delta() || self.lookups_delta.has_delta()
    }
}

/// Service account metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountMetadata {
    /// `c`: Service code hash
    pub code_hash: Hash32,
    /// `b`: Service account token balance
    pub balance: Balance,
    /// `g`: Service-specific gas limit for `accumulate`
    pub gas_limit_accumulate: UnsignedGas,
    /// `m`: Service-specific gas limit for `on_transfer`
    pub gas_limit_on_transfer: UnsignedGas,
    /// `i`: The number of entries stored in account storages
    pub items_footprint: u32,
    /// `o`: The number of total octets used by account storages
    pub octets_footprint: u64,
}
impl_account_state_component!(AccountMetadata, AccountMetadata);

impl JamEncode for AccountMetadata {
    fn size_hint(&self) -> usize {
        self.code_hash.size_hint() + 8 * 4 + 4
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.code_hash.encode_to(dest)?;
        self.balance.encode_to_fixed(dest, 8)?;
        self.gas_limit_accumulate.encode_to_fixed(dest, 8)?;
        self.gas_limit_on_transfer.encode_to_fixed(dest, 8)?;
        self.octets_footprint.encode_to_fixed(dest, 8)?;
        self.items_footprint.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for AccountMetadata {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            code_hash: Hash32::decode(input)?,
            balance: Balance::decode_fixed(input, 8)?,
            gas_limit_accumulate: UnsignedGas::decode_fixed(input, 8)?,
            gas_limit_on_transfer: UnsignedGas::decode_fixed(input, 8)?,
            octets_footprint: u64::decode_fixed(input, 8)?,
            items_footprint: u32::decode_fixed(input, 4)?,
        })
    }
}

impl AccountMetadata {
    pub fn balance(&self) -> Balance {
        self.balance
    }

    /// Adds balance to the account and returns the updated balance.
    /// Returns `None` if the balance overflows.
    #[allow(clippy::manual_inspect)]
    pub fn add_balance(&mut self, amount: Balance) -> Option<Balance> {
        self.balance.checked_add(amount).map(|new_balance| {
            self.balance = new_balance;
            new_balance
        })
    }

    /// Get the account threshold balance (t)
    pub fn threshold_balance(&self) -> Balance {
        MIN_BASIC_BALANCE
            + MIN_BALANCE_PER_ITEM * self.items_footprint as Balance
            + MIN_BALANCE_PER_OCTET * self.octets_footprint
    }

    /// Calculates the state delta of the storage footprints caused by replacing `prev_entry`
    /// with the `new_entry` in the account storages.
    pub fn calculate_storage_usage_delta<T>(
        prev_entry: Option<&T>,
        new_entry: Option<&T>,
    ) -> Option<StorageUsageDelta>
    where
        T: StorageFootprint,
    {
        match (prev_entry, new_entry) {
            (Some(prev), None) => {
                // Case 1: Removing the existing storage or lookups entry
                Some(StorageUsageDelta::new(
                    -1,
                    -(prev.storage_octets_usage() as i64),
                ))
            }
            (Some(prev), Some(new)) => {
                // Case 2: Updating the existing storage or lookups entry
                Some(StorageUsageDelta::new(
                    0,
                    new.storage_octets_usage() as i64 - prev.storage_octets_usage() as i64,
                ))
            }
            (None, None) => {
                // Case 3: Attempted to delete a storage or lookups entry that doesn't exist.
                None
            }
            (None, Some(new)) => {
                // Case 4: Adding a new storage or lookups entry
                Some(StorageUsageDelta::new(1, new.storage_octets_usage() as i64))
            }
        }
    }

    /// Simulates mutating account storages to get the estimated threshold balance required after
    /// the mutation. Used to evaluate validity of such mutation in host functions that update the
    /// account storages.
    pub fn simulate_threshold_balance_after_mutation(
        &self,
        storage_usage_delta: Option<StorageUsageDelta>,
        lookups_usage_delta: Option<StorageUsageDelta>,
    ) -> Balance {
        let mut simulated = self.clone();
        let account_storage_usage_delta = AccountStorageUsageDelta {
            storage_delta: storage_usage_delta.unwrap_or_default(),
            lookups_delta: lookups_usage_delta.unwrap_or_default(),
        };

        simulated.update_footprints(AccountFootprintDelta::from(account_storage_usage_delta));
        simulated.threshold_balance()
    }

    pub const fn get_initial_threshold_balance(code_lookup_len: u32) -> Balance {
        MIN_BASIC_BALANCE
            + MIN_BALANCE_PER_ITEM * 2
            + MIN_BALANCE_PER_OCTET * (code_lookup_len as Balance + 81)
    }

    fn apply_items_footprint_delta(footprint: &mut u32, delta: i32) {
        if delta < 0 {
            *footprint = footprint.saturating_sub(delta.unsigned_abs());
        } else {
            *footprint = footprint.saturating_add(delta as u32);
        }
    }

    fn apply_octets_footprint_delta(footprint: &mut u64, delta: i64) {
        if delta < 0 {
            *footprint = footprint.saturating_sub(delta.unsigned_abs());
        } else {
            *footprint = footprint.saturating_add(delta as u64);
        }
    }

    /// Updates service account storage footprints and returns a boolean flag
    /// to indicate whether footprints are updated.
    pub fn update_footprints(&mut self, delta: AccountFootprintDelta) -> bool {
        if delta.has_delta() {
            Self::apply_items_footprint_delta(
                &mut self.items_footprint,
                delta.storage_delta.items_footprint_delta,
            );
            Self::apply_octets_footprint_delta(
                &mut self.octets_footprint,
                delta.storage_delta.octets_footprint_delta,
            );
            Self::apply_items_footprint_delta(
                &mut self.items_footprint,
                delta.lookups_delta.items_footprint_delta,
            );
            Self::apply_octets_footprint_delta(
                &mut self.octets_footprint,
                delta.lookups_delta.octets_footprint_delta,
            );
            true
        } else {
            false
        }
    }

    /// Used by the PVM `host_info` execution.
    pub fn encode_for_info_hostcall(&self) -> Result<Vec<u8>, JamCodecError> {
        let mut buf = vec![];
        self.code_hash.encode_to(&mut buf)?; // c
        self.balance.encode_to(&mut buf)?; // b
        self.threshold_balance().encode_to(&mut buf)?; // t
        self.gas_limit_accumulate.encode_to(&mut buf)?; // g
        self.gas_limit_on_transfer.encode_to(&mut buf)?; // m
        self.octets_footprint.encode_to(&mut buf)?; // o
        self.items_footprint.encode_to(&mut buf)?; // i

        Ok(buf)
    }
}

/// Represents storage entry types that are used for metering storage usage footprint.
pub trait StorageFootprint {
    fn storage_octets_usage(&self) -> usize;
}

/// A marker trait for types that represent account state components used in PVM invocation contexts.
///
/// This is used to group types that are part of an account's state and are eligible for
/// manipulation or evaluation in a sandboxed PVM host-call execution context.
pub trait AccountPartialState {}
impl AccountPartialState for AccountMetadata {}
impl AccountPartialState for AccountStorageEntry {}
impl AccountPartialState for AccountPreimagesEntry {}
impl AccountPartialState for AccountLookupsEntryExt {}

#[derive(Clone, Default, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountStorageEntry {
    pub value: Octets,
}
impl_account_state_component!(AccountStorageEntry, AccountStorageEntry);

impl AccountStorageEntry {
    pub fn new(value: Octets) -> Self {
        Self { value }
    }
}

impl StorageFootprint for AccountStorageEntry {
    fn storage_octets_usage(&self) -> usize {
        self.value.len()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct AccountPreimagesEntry {
    pub value: Octets,
}
impl_account_state_component!(AccountPreimagesEntry, AccountPreimagesEntry);

impl AccountPreimagesEntry {
    pub fn new(value: Octets) -> Self {
        Self { value }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
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

impl AccountLookupsEntry {
    pub fn new(value: Vec<Timeslot>) -> Self {
        Self { value }
    }
}

/// An extended type of `AccountLookupsEntry` that include additional metadata about the preimage
/// entry size in octets. This is useful for tracking storage usage and calculating threshold balance
/// of an account. This is NOT serialized as part of the global state.
#[derive(Clone)]
pub struct AccountLookupsEntryExt {
    /// Length of the preimage data, which is also part of the lookups key
    pub preimage_length: u32,
    pub entry: AccountLookupsEntry,
}

impl Deref for AccountLookupsEntryExt {
    type Target = AccountLookupsEntry;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl DerefMut for AccountLookupsEntryExt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entry
    }
}

impl StorageFootprint for AccountLookupsEntryExt {
    fn storage_octets_usage(&self) -> usize {
        self.preimage_length as usize
    }
}

impl AccountLookupsEntryExt {
    pub fn from_entry(key: LookupsKey, entry: AccountLookupsEntry) -> Self {
        Self {
            preimage_length: key.1,
            entry,
        }
    }

    pub fn into_entry(self) -> AccountLookupsEntry {
        self.entry
    }
}

/// Identifier of services that are allowed to conduct privileged state transitions,
/// along with metadata of the always-accumulate services.
///
/// Represents `χ` of the GP.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PrivilegedServices {
    /// `m`: A privileged service that can alter privileged services state.
    pub manager_service: ServiceId,
    /// `a`: A privileged service that can alter the auth queue.
    pub assign_service: ServiceId,
    /// `v`: A privileged service that can alter the staging validator set.
    pub designate_service: ServiceId,
    /// **`g`**: A mapping of always-accumulate services and their basic gas usages.
    pub always_accumulate_services: HashMap<ServiceId, UnsignedGas>,
}
impl_simple_state_component!(PrivilegedServices, PrivilegedServices);
