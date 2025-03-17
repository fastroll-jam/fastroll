use rjam_common::{Hash32, LookupsKey, ServiceId};
use rjam_pvm_core::types::error::PartialStateError;
use rjam_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{
        AccountLookupsEntryExt, AccountMetadata, AccountPartialState, AccountPreimagesEntry,
        AccountStorageEntry, AccountStorageUsageDelta, AuthQueue, PrivilegedServices, StagingSet,
        StorageFootprint, StorageUsageDelta, Timeslot,
    },
};
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub trait SandboxEntryAccessor<T>
where
    T: AccountPartialState + Clone,
{
    fn from_clean(entry: T) -> Self;

    fn status(&self) -> &SandboxEntryStatus;

    fn get_cloned(&self) -> Option<T>;

    fn as_ref(&self) -> Option<&T>;

    fn as_mut(&mut self) -> Option<&mut T>;
}

#[derive(Clone, PartialEq)]
pub enum SandboxEntryStatus {
    /// State entry is copied from the state manager, with no modification.
    Clean,
    /// State entry doesn't exist in the state manager and is created during the accumulation.
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
pub struct SandboxEntry<T>
where
    T: AccountPartialState + Clone,
{
    value: Option<T>,
    status: SandboxEntryStatus,
}

impl<T> SandboxEntryAccessor<T> for SandboxEntry<T>
where
    T: AccountPartialState + Clone,
{
    fn from_clean(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: SandboxEntryStatus::Clean,
        }
    }

    fn status(&self) -> &SandboxEntryStatus {
        &self.status
    }

    fn get_cloned(&self) -> Option<T> {
        self.value.clone()
    }

    fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    fn as_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }
}

impl<T> SandboxEntry<T>
where
    T: AccountPartialState + Clone,
{
    pub fn new_added(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: SandboxEntryStatus::Added,
        }
    }

    pub fn new_updated(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: SandboxEntryStatus::Updated,
        }
    }

    pub fn new_removed() -> Self {
        Self {
            value: None,
            status: SandboxEntryStatus::Removed,
        }
    }

    pub fn mark_updated(&mut self) {
        // `Added` status should remain as `Added`
        if !(self.status == SandboxEntryStatus::Added || self.status == SandboxEntryStatus::Updated)
        {
            self.status = SandboxEntryStatus::Updated;
        }
    }

    pub fn mark_removed(&mut self) {
        if self.status != SandboxEntryStatus::Removed {
            self.value = None;
            self.status = SandboxEntryStatus::Removed;
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct SandboxEntryVersioned<T>
where
    T: AccountPartialState + StorageFootprint + Clone,
{
    entry: SandboxEntry<T>,
    clean_snapshot: Option<T>,
}

impl<T> SandboxEntryAccessor<T> for SandboxEntryVersioned<T>
where
    T: AccountPartialState + StorageFootprint + Clone,
{
    fn from_clean(entry: T) -> Self {
        Self {
            entry: SandboxEntry::from_clean(entry),
            clean_snapshot: None,
        }
    }

    fn status(&self) -> &SandboxEntryStatus {
        &self.entry.status
    }

    fn get_cloned(&self) -> Option<T> {
        self.entry.value.clone()
    }

    fn as_ref(&self) -> Option<&T> {
        self.entry.value.as_ref()
    }

    fn as_mut(&mut self) -> Option<&mut T> {
        self.entry.value.as_mut()
    }
}

#[allow(dead_code)]
impl<T> SandboxEntryVersioned<T>
where
    T: AccountPartialState + StorageFootprint + Clone,
{
    pub fn new_added(entry: T) -> Self {
        Self {
            entry: SandboxEntry::new_added(entry),
            clean_snapshot: None,
        }
    }

    pub fn new_updated(updated: T, clean: T) -> Self {
        Self {
            entry: SandboxEntry::new_updated(updated),
            clean_snapshot: Some(clean),
        }
    }

    pub fn new_removed(clean: T) -> Self {
        Self {
            entry: SandboxEntry::new_removed(),
            clean_snapshot: Some(clean),
        }
    }

    fn storage_usage_delta(&self) -> Option<StorageUsageDelta> {
        match &self.entry.status {
            SandboxEntryStatus::Clean => None,
            SandboxEntryStatus::Added => {
                AccountMetadata::calculate_storage_usage_delta(None, self.as_ref())
            }
            SandboxEntryStatus::Updated => AccountMetadata::calculate_storage_usage_delta(
                self.clean_snapshot.as_ref(),
                self.as_ref(),
            ),
            SandboxEntryStatus::Removed => {
                AccountMetadata::calculate_storage_usage_delta(self.clean_snapshot.as_ref(), None)
            }
        }
    }
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
    pub metadata: SandboxEntry<AccountMetadata>,
    pub storage: HashMap<Hash32, SandboxEntryVersioned<AccountStorageEntry>>,
    pub preimages: HashMap<Hash32, SandboxEntry<AccountPreimagesEntry>>,
    pub lookups: HashMap<LookupsKey, SandboxEntryVersioned<AccountLookupsEntryExt>>,
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
            metadata: SandboxEntry::from_clean(metadata),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
        })
    }

    pub fn storage_usage_delta_aggregated(&self) -> AccountStorageUsageDelta {
        // storage usage delta
        let (storage_items_count_delta, storage_octets_delta) = self
            .storage
            .values()
            .filter_map(|entry| entry.storage_usage_delta())
            .fold((0, 0), |(items_acc, octets_acc), delta| {
                (
                    items_acc + delta.items_count_delta,
                    octets_acc + delta.octets_delta,
                )
            });

        // lookups usage delta
        let (lookups_items_count_delta, lookups_octets_delta) = self
            .lookups
            .values()
            .filter_map(|entry| entry.storage_usage_delta())
            .fold((0, 0), |(items_acc, octets_acc), delta| {
                (
                    items_acc + delta.items_count_delta,
                    octets_acc + delta.octets_delta,
                )
            });

        AccountStorageUsageDelta {
            storage_delta: StorageUsageDelta::new(storage_items_count_delta, storage_octets_delta),
            lookups_delta: StorageUsageDelta::new(lookups_items_count_delta, lookups_octets_delta),
        }
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

    pub async fn get_mut_account_sandbox(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountSandbox>, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_manager, service_id)
            .await?;
        Ok(self.get_mut(&service_id))
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
    /// entries wrapped with types that implement `SandboxEntryAccessor<T>` trait.
    /// This can represent state entry copied from the global state (state manager)
    /// or its mutated version (added, updated or removed) in the sandboxed environment.
    ///
    /// If an item of the given key is not found from the `map`, it attempts to load it from the global
    /// state by invoking `load_from_global` and then insert the found entry to the `map` if exists.
    async fn get_or_load_entry<K, V, T, F, Fut>(
        map: &mut HashMap<K, V>,
        key: &K,
        load_from_global: F,
    ) -> Result<Option<T>, PartialStateError>
    where
        K: Eq + Hash + Clone,
        V: SandboxEntryAccessor<T> + Clone,
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
            let clean_entry: V = SandboxEntryAccessor::from_clean(value);
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
                Self::get_or_load_entry(&mut sandbox.storage, storage_key, || {
                    state_manager.get_account_storage_entry(service_id, storage_key)
                })
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
        let entry = if let Some(prev_entry) = self
            .get_account_storage_entry(state_manager.clone(), service_id, &storage_key)
            .await?
        {
            // Entry with the key already exists in the global state
            SandboxEntryVersioned::new_updated(new_entry, prev_entry)
        } else {
            SandboxEntryVersioned::new_added(new_entry)
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
        if let Some(prev_entry) = self
            .get_account_storage_entry(state_manager.clone(), service_id, &storage_key)
            .await?
        {
            // Entry with the key already exists in the global state
            let entry = SandboxEntryVersioned::new_removed(prev_entry);
            let sandbox = self
                .get_mut_account_sandbox(state_manager, service_id)
                .await?
                .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
            let removed = sandbox
                .storage
                .insert(storage_key, entry)
                .expect("Should exist");
            return Ok(removed.get_cloned());
        }

        // Attempted to remove an entry that is not found in the sandbox
        Ok(None)
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
                Self::get_or_load_entry(&mut sandbox.preimages, preimages_key, || {
                    state_manager.get_account_preimages_entry(service_id, preimages_key)
                })
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
            SandboxEntry::new_updated(new_entry)
        } else {
            SandboxEntry::new_added(new_entry)
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
            .insert(preimages_key, SandboxEntry::new_removed());

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
        lookups_storage_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager.clone(), service_id)
            .await?;
        match sandbox {
            Some(sandbox) => {
                Self::get_or_load_entry(&mut sandbox.lookups, lookups_storage_key, || async {
                    Ok(state_manager
                        .get_account_lookups_entry(service_id, lookups_storage_key)
                        .await?
                        .map(|entry| {
                            AccountLookupsEntryExt::from_entry(*lookups_storage_key, entry)
                        }))
                })
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
        lookups_key: LookupsKey,
        new_entry: AccountLookupsEntryExt,
    ) -> Result<(), PartialStateError> {
        let entry = if let Some(prev_entry) = self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        {
            // Entry with the key already exists in the global state
            SandboxEntryVersioned::new_updated(new_entry, prev_entry)
        } else {
            SandboxEntryVersioned::new_added(new_entry)
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
        lookups_key: LookupsKey,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        if let Some(prev_entry) = self
            .get_account_lookups_entry(state_manager.clone(), service_id, &lookups_key)
            .await?
        {
            // Entry with the key already exists in the global state
            let entry = SandboxEntryVersioned::new_removed(prev_entry);
            let sandbox = self
                .get_mut_account_sandbox(state_manager, service_id)
                .await?
                .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
            let removed = sandbox
                .lookups
                .insert(lookups_key, entry)
                .expect("Should exist");
            return Ok(removed.get_cloned());
        }

        // Attempted to remove an entry that is not found in the sandbox
        Ok(None)
    }

    /// Pushes a new timeslot to the lookups entry value sequence and returns
    /// the length of the timeslot vector after appending a new entry.
    /// Returns `None` if such lookups entry is not found.
    pub async fn push_timeslot_to_account_lookups_entry(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
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
        lookups_key: LookupsKey,
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
        lookups_key: LookupsKey,
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

    pub async fn eject_account(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        sandbox.metadata = SandboxEntry::new_removed();

        // Mark all storage entries associated with the service_id as removed.
        sandbox.storage.values_mut().for_each(|v| {
            if let Some(prev_entry) = v.get_cloned() {
                *v = SandboxEntryVersioned::new_removed(prev_entry)
            }
        });
        sandbox
            .preimages
            .values_mut()
            .for_each(|v| *v = SandboxEntry::new_removed());
        sandbox.lookups.values_mut().for_each(|v| {
            if let Some(prev_entry) = v.get_cloned() {
                *v = SandboxEntryVersioned::new_removed(prev_entry)
            }
        });

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
