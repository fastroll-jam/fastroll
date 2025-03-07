use rjam_common::{Hash32, ServiceId};
use rjam_pvm_core::types::error::PartialStateError;
use rjam_state::{error::StateManagerError, StateManager};
use rjam_types::state::*;
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::Arc,
};

#[derive(Clone, PartialEq)]
pub enum PartialStateEntryStatus {
    /// State entry is copied from the state manager, with no modification.
    Clean,
    /// State entry doesn't exist in the state manager and is created during the execution.
    Added,
    /// State entry is copied from the state manager and then modified.
    Updated,
    /// State entry is copied from the state manager and then removed.
    Removed,
}

/// Represents a sandboxed copy of an account state for use in host-call execution contexts.
/// The account state may originate from the global state or be created/updated/removed within the
/// execution context.
#[derive(Clone)]
pub struct PartialStateEntry<T: AccountPartialState + Clone> {
    value: Option<T>,
    status: PartialStateEntryStatus,
}

impl<T: AccountPartialState + Clone> PartialStateEntry<T> {
    pub fn new_clean(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: PartialStateEntryStatus::Clean,
        }
    }

    pub fn new_added(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: PartialStateEntryStatus::Added,
        }
    }

    pub fn new_updated(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: PartialStateEntryStatus::Updated,
        }
    }

    pub fn new_removed() -> Self {
        Self {
            value: None,
            status: PartialStateEntryStatus::Removed,
        }
    }

    pub fn status(&self) -> &PartialStateEntryStatus {
        &self.status
    }

    pub fn get_cloned(&self) -> Option<T> {
        self.value.clone()
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }

    fn mark_updated(&mut self) {
        // `Added` status should remain as `Added`
        if !(self.status == PartialStateEntryStatus::Added
            || self.status == PartialStateEntryStatus::Updated)
        {
            self.status = PartialStateEntryStatus::Updated;
        }
    }

    fn mark_removed(&mut self) {
        if self.status != PartialStateEntryStatus::Removed {
            self.value = None;
            self.status = PartialStateEntryStatus::Removed;
        }
    }
}

pub struct AccountFootprintDelta {
    pub storage_items_count_delta: i32,
    pub storage_octets_delta: i64,
    pub lookups_items_count_delta: i32,
    pub lookups_octets_delta: i64,
}

/// Represents a sandboxed environment of a service account, including its metadata
/// and associated storage entries.
///
/// It is primarily used in the `accumulate` and `on_transfer` PVM invocation context for
/// state mutations of service accounts. The global state serialization doesn't require
/// the service metadata and storage entries to be placed together,
/// which makes this type to be specific to the accumulation process.
#[derive(Clone)]
pub struct AccountSandbox {
    pub metadata: PartialStateEntry<AccountMetadata>,
    pub storage: HashMap<Hash32, PartialStateEntry<AccountStorageEntry>>,
    pub preimages: HashMap<Hash32, PartialStateEntry<AccountPreimagesEntry>>,
    pub lookups: HashMap<(Hash32, u32), PartialStateEntry<AccountLookupsEntry>>,
}

impl AccountSandbox {
    pub async fn from_service_id(
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Self, PartialStateError> {
        let metadata = state_manager
            .get_account_metadata(service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        Ok(Self {
            metadata: PartialStateEntry::new_clean(metadata),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
        })
    }

    pub fn calculate_storage_footprint_delta(&self) -> AccountFootprintDelta {
        unimplemented!()
    }
}

/// Represents a collection of service account sandboxes
#[derive(Clone, Default)]
pub struct AccountsSandboxMap {
    accounts: HashMap<ServiceId, AccountSandbox>,
}

impl Deref for AccountsSandboxMap {
    type Target = HashMap<ServiceId, AccountSandbox>;

    fn deref(&self) -> &Self::Target {
        &self.accounts
    }
}

impl DerefMut for AccountsSandboxMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.accounts
    }
}

impl AccountsSandboxMap {
    /// Initializes the service account sandbox state by copying the account metadata from the
    /// global state and initializing empty HashMap types for storage types.
    async fn ensure_account_sandbox_initialized(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if !self.contains_key(&service_id) && state_manager.account_exists(service_id).await? {
            self.insert(
                service_id,
                AccountSandbox::from_service_id(state_manager, service_id).await?,
            );
        }
        Ok(())
    }

    pub async fn get_account_sandbox(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Option<&AccountSandbox>, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_manager, service_id)
            .await?;
        Ok(self.get(&service_id))
    }

    pub fn get_account_sandbox_unchecked(&self, service_id: ServiceId) -> Option<&AccountSandbox> {
        self.get(&service_id)
    }

    async fn get_mut_account_sandbox(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountSandbox>, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_manager, service_id)
            .await?;
        Ok(self.get_mut(&service_id))
    }

    pub fn get_mut_account_sandbox_unchecked(
        &mut self,
        service_id: ServiceId,
    ) -> Option<&mut AccountSandbox> {
        self.get_mut(&service_id)
    }

    /// Gets a reference to an `AccountMetadata` from the account sandbox.
    /// Returns `None` if the account doesn't exist in the global state or was removed from the
    /// partial state.
    pub async fn get_account_metadata(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Option<&AccountMetadata>, PartialStateError> {
        match self.get_account_sandbox(state_manager, service_id).await? {
            Some(sandbox) => Ok(sandbox.metadata.as_ref()),
            None => Ok(None),
        }
    }

    /// Gets a mutable reference to an `AccountMetadata` from the account sandbox.
    /// Returns `None` if the account doesn't exist in the global state or was removed from the
    /// partial state.
    pub async fn get_mut_account_metadata(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountMetadata>, PartialStateError> {
        match self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
        {
            Some(sandbox) => Ok(sandbox.metadata.as_mut()),
            None => Ok(None),
        }
    }

    pub async fn mark_account_metadata_updated(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if let Some(sandbox) = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
        {
            sandbox.metadata.mark_updated();
        }
        Ok(())
    }

    pub async fn mark_account_metadata_removed(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if let Some(sandbox) = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
        {
            sandbox.metadata.mark_removed();
        }
        Ok(())
    }

    /// Attempts to retrieve an entry of type `T` from the map or the global state using the given key.
    ///
    /// The `map` is one of the account storage types stored in `AccountSandbox`, which stores storage
    /// entries wrapped with `PartialStateEntry<T>` type. This can represent state entry copied from
    /// the global state (state manager) or its mutated version (added, updated or removed) in the
    /// sandboxed environment.
    ///
    /// If an item of the given key is not found from the `map`, it attempts to load it from the global
    /// state by invoking `load_from_global` and then insert the found entry to the `map` if exists.
    async fn get_or_load_entry<K, T, F, Fut>(
        map: &mut HashMap<K, PartialStateEntry<T>>,
        key: &K,
        load_from_global: F,
    ) -> Result<Option<T>, PartialStateError>
    where
        K: Eq + Hash + Clone,
        T: AccountPartialState + Clone,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<T>, StateManagerError>>,
    {
        // Check if the entry is already in the map of the account sandbox.
        // If the entry is removed from the partial state, `None` is returned.
        if let Some(entry) = map.get(key) {
            return Ok(entry.get_cloned());
        }

        // If not found in the map, attempt to load it from the global state
        let entry_from_global = load_from_global().await?;
        if let Some(value) = entry_from_global {
            let clean_entry = PartialStateEntry::new_clean(value);
            map.insert(key.clone(), clean_entry.clone());
            Ok(clean_entry.get_cloned())
        } else {
            // Not found in the global state either
            Ok(None)
        }
    }

    pub async fn get_account_storage_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        storage_key: &Hash32,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager.clone(), service_id)
            .await?;
        match sandbox {
            Some(sandbox) => {
                Self::get_or_load_entry(
                    &mut sandbox.storage,
                    storage_key,
                    async || -> Result<Option<AccountStorageEntry>, StateManagerError> {
                        state_manager
                            .get_account_storage_entry(service_id, storage_key)
                            .await
                    },
                )
                .await
            }
            None => Ok(None),
        }
    }

    /// Inserts a new storage entry to the account sandbox and optionally returns the replaced entry, if exists.
    pub async fn insert_account_storage_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        storage_key: Hash32,
        new_entry: AccountStorageEntry,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let entry = if self
            .get_account_storage_entry(state_manager.clone(), service_id, &storage_key)
            .await?
            .is_some()
        {
            // Entry with the key already exists in the global state
            PartialStateEntry::new_updated(new_entry)
        } else {
            PartialStateEntry::new_added(new_entry)
        };

        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;

        let maybe_replaced = sandbox.storage.insert(storage_key, entry);

        if let Some(replaced) = maybe_replaced {
            Ok(replaced.get_cloned())
        } else {
            Ok(None)
        }
    }

    /// Removes a storage entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_storage_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        storage_key: Hash32,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let maybe_removed = sandbox
            .storage
            .insert(storage_key, PartialStateEntry::new_removed());

        if let Some(removed) = maybe_removed {
            Ok(removed.get_cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn get_account_preimages_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager.clone(), service_id)
            .await?;
        match sandbox {
            Some(sandbox) => {
                Self::get_or_load_entry(
                    &mut sandbox.preimages,
                    preimages_key,
                    async || -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
                        state_manager
                            .get_account_preimages_entry(service_id, preimages_key)
                            .await
                    },
                )
                .await
            }
            None => Ok(None),
        }
    }

    /// Inserts a new preimages entry to the account sandbox and optionally returns the replaced entry, if exists.
    pub async fn insert_account_preimages_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        preimages_key: Hash32,
        new_entry: AccountPreimagesEntry,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let entry = if self
            .get_account_preimages_entry(state_manager.clone(), service_id, &preimages_key)
            .await?
            .is_some()
        {
            // Entry with the key already exists in the global state
            PartialStateEntry::new_updated(new_entry)
        } else {
            PartialStateEntry::new_added(new_entry)
        };

        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;

        let maybe_replaced = sandbox.preimages.insert(preimages_key, entry);

        if let Some(replaced) = maybe_replaced {
            Ok(replaced.get_cloned())
        } else {
            Ok(None)
        }
    }

    /// Removes a preimages entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_preimages_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        preimages_key: Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let maybe_removed = sandbox
            .preimages
            .insert(preimages_key, PartialStateEntry::new_removed());

        if let Some(removed) = maybe_removed {
            Ok(removed.get_cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn get_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_storage_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager.clone(), service_id)
            .await?;
        match sandbox {
            Some(sandbox) => {
                Self::get_or_load_entry(
                    &mut sandbox.lookups,
                    lookups_storage_key,
                    async || -> Result<Option<AccountLookupsEntry>, StateManagerError> {
                        state_manager
                            .get_account_lookups_entry(service_id, lookups_storage_key)
                            .await
                    },
                )
                .await
            }
            None => Ok(None),
        }
    }

    /// Inserts a new lookups entry to the account sandbox.
    pub async fn insert_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        new_entry: AccountLookupsEntry,
    ) -> Result<(), PartialStateError> {
        let entry = if self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
            .is_some()
        {
            // Entry with the key already exists in the global state
            PartialStateEntry::new_updated(new_entry)
        } else {
            PartialStateEntry::new_added(new_entry)
        };

        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;

        sandbox.lookups.insert(lookups_key, entry);
        Ok(())
    }

    /// Removes a lookups entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let maybe_removed = sandbox
            .lookups
            .insert(lookups_key, PartialStateEntry::new_removed());

        if let Some(removed) = maybe_removed {
            Ok(removed.get_cloned())
        } else {
            Ok(None)
        }
    }

    /// Pushes a new timeslot to the lookups entry value sequence and returns
    /// the length of the timeslot vector after appending a new entry.
    /// Returns `None` if such lookups entry is not found.
    pub async fn push_timeslot_to_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        timeslot: Timeslot,
    ) -> Result<Option<usize>, PartialStateError> {
        let mut lookups_entry = match self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        {
            Some(entry) => entry,
            None => {
                return Ok(None);
            }
        };
        lookups_entry.value.push(timeslot);

        let new_timeslot_vec_len = lookups_entry.value.len();
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(Some(new_timeslot_vec_len))
    }

    pub async fn extend_timeslots_to_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        timeslots: Vec<Timeslot>,
    ) -> Result<Option<usize>, PartialStateError> {
        let mut lookups_entry = match self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        {
            Some(entry) => entry,
            None => {
                return Ok(None);
            }
        };
        lookups_entry.value.extend(timeslots);

        let new_timeslot_vec_len = lookups_entry.value.len();
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(Some(new_timeslot_vec_len))
    }

    pub async fn drain_account_lookups_entry_timeslots(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
    ) -> Result<bool, PartialStateError> {
        let mut lookups_entry = match self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        {
            Some(entry) => entry,
            None => {
                return Ok(false);
            }
        };
        lookups_entry.value = vec![];
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(true)
    }

    // TODO: Remove if not used
    pub async fn update_account_lookups_footprint_from_entries(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: &(Hash32, u32),
        prev_lookups_entry: Option<&AccountLookupsEntry>,
        new_lookups_entry: Option<&AccountLookupsEntry>,
    ) -> Result<(), PartialStateError> {
        // Construct `AccountLookupsOctetsUsage` types from the previous and the new entries.
        let prev_lookups_octets_usage =
            prev_lookups_entry
                .cloned()
                .map(|p| AccountLookupsOctetsUsage {
                    preimage_length: lookups_key.1,
                    entry: p,
                });

        let new_lookups_octets_usage =
            new_lookups_entry.map(|new_entry| AccountLookupsOctetsUsage {
                preimage_length: lookups_key.1,
                entry: new_entry.clone(),
            });

        let (item_count_delta, octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_lookups_octets_usage.as_ref(),
                new_lookups_octets_usage.as_ref(),
            )
            .ok_or(PartialStateError::MissingAccountEntryDeletion)?;

        let metadata = self
            .get_mut_account_metadata(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;

        metadata.update_lookups_footprint(item_count_delta, octets_count_delta);
        Ok(())
    }

    pub async fn eject_account(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        sandbox.metadata = PartialStateEntry::new_removed();

        // Mark all storage entries associated with the service_id as removed.
        sandbox
            .storage
            .values_mut()
            .for_each(|v| *v = PartialStateEntry::new_removed());
        sandbox
            .preimages
            .values_mut()
            .for_each(|v| *v = PartialStateEntry::new_removed());
        sandbox
            .lookups
            .values_mut()
            .for_each(|v| *v = PartialStateEntry::new_removed());

        Ok(())
    }
}

/// Represents a mutable copy of a subset of the global state used during the accumulation process.
///
/// This provides a sandboxed environment for performing state mutations safely, yielding the final
/// change set of the state on success and discarding the mutations on failure.
#[derive(Clone, Default)]
pub struct AccumulatePartialState {
    /// **`d`**: Sandboxed copy of service accounts states
    pub accounts_sandbox: AccountsSandboxMap,
    /// **`i`**: New allocation of `StagingSet` after accumulation
    pub new_staging_set: Option<StagingSet>,
    /// **`q`**: New allocation of `AuthQueue` after accumulation
    pub new_auth_queue: Option<AuthQueue>,
    /// **`x`**: New allocation of `PrivilegedServices` after accumulation
    pub new_privileges: Option<PrivilegedServices>,
}

impl AccumulatePartialState {
    /// Initializes `AccumulatePartialState` with the accumulator service account sandbox entry.
    pub async fn new_from_service_id(
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Self, PartialStateError> {
        let mut accounts_sandbox = HashMap::new();
        let account_sandbox = AccountSandbox::from_service_id(state_manager, service_id).await?;
        accounts_sandbox.insert(service_id, account_sandbox);
        Ok(Self {
            accounts_sandbox: AccountsSandboxMap {
                accounts: accounts_sandbox,
            },
            ..Default::default()
        })
    }
}
