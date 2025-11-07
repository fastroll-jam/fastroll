use crate::error::PartialStateError;
use fr_codec::prelude::*;
use fr_common::{Balance, CoreIndex, LookupsKey, PreimagesKey, ServiceId, StorageKey};
use fr_state::{
    error::StateManagerError,
    provider::HostStateProvider,
    types::{
        privileges::{AlwaysAccumulateServices, AssignServices, PrivilegedServices},
        AccountCode, AccountFootprintDelta, AccountLookupsEntry, AccountLookupsEntryExt,
        AccountLookupsEntryTimeslots, AccountMetadata, AccountPartialState, AccountPreimagesEntry,
        AccountStorageEntryExt, AccountStorageUsageDelta, AuthQueue, StagingSet, Timeslot,
    },
};
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    marker::PhantomData,
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

#[derive(Clone, Debug, PartialEq)]
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
struct SandboxEntry<T>
where
    T: AccountPartialState + Clone,
{
    value: Option<T>,
    status: SandboxEntryStatus,
}

impl<T> SandboxEntry<T>
where
    T: AccountPartialState + Clone,
{
    fn new_added(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: SandboxEntryStatus::Added,
        }
    }

    fn new_updated(entry: T) -> Self {
        Self {
            value: Some(entry),
            status: SandboxEntryStatus::Updated,
        }
    }

    fn new_removed() -> Self {
        Self {
            value: None,
            status: SandboxEntryStatus::Removed,
        }
    }
}

/// Sandbox entry type that optionally contains a clean snapshot of the state entry, which is
/// synced with the global state prior to accumulation. The clean state is required to correctly
/// calculate storage footprint changes and to determine final entry status after mutations.
#[derive(Clone)]
pub struct SandboxEntryVersioned<T>
where
    T: AccountPartialState + Clone,
{
    entry: SandboxEntry<T>,
    pub clean_snapshot: Option<T>,
}

impl<T> SandboxEntryAccessor<T> for SandboxEntryVersioned<T>
where
    T: AccountPartialState + Clone,
{
    fn from_clean(entry: T) -> Self {
        Self {
            entry: SandboxEntry {
                value: Some(entry),
                status: SandboxEntryStatus::Clean,
            },
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

impl<T> SandboxEntryVersioned<T>
where
    T: AccountPartialState + Clone,
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

    pub fn mark_updated(&mut self) {
        // `Added` status should remain as `Added`
        if !(self.entry.status == SandboxEntryStatus::Added
            || self.entry.status == SandboxEntryStatus::Updated)
        {
            self.entry.status = SandboxEntryStatus::Updated;
        }
    }

    pub fn mark_removed(&mut self) {
        if self.entry.status != SandboxEntryStatus::Removed {
            self.entry.value = None;
            self.entry.status = SandboxEntryStatus::Removed;
        }
    }
}

/// Represents a sandboxed environment of a service account, including its metadata
/// and associated storage entries.
///
/// It is primarily used in the `accumulate` PVM invocation contexts for
/// state mutations of service accounts. The global state serialization doesn't require
/// the service metadata and storage entries to be placed together,
/// which makes this type to be specific to the `accumulate` process.
pub struct AccountSandbox<S: HostStateProvider> {
    pub metadata: SandboxEntryVersioned<AccountMetadata>,
    pub storage: HashMap<StorageKey, SandboxEntryVersioned<AccountStorageEntryExt>>,
    pub preimages: HashMap<PreimagesKey, SandboxEntryVersioned<AccountPreimagesEntry>>,
    pub lookups: HashMap<LookupsKey, SandboxEntryVersioned<AccountLookupsEntryExt>>,
    pub _phantom: PhantomData<S>,
}

impl<S: HostStateProvider> Clone for AccountSandbox<S> {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            storage: self.storage.clone(),
            preimages: self.preimages.clone(),
            lookups: self.lookups.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S: HostStateProvider> AccountSandbox<S> {
    pub async fn from_service_id(
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Self, PartialStateError> {
        let metadata = state_provider
            .get_account_metadata(service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;
        Ok(Self {
            metadata: SandboxEntryVersioned::from_clean(metadata),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
            _phantom: PhantomData,
        })
    }
}

/// Represents a collection of service account sandboxes
pub struct AccountsSandboxMap<S: HostStateProvider> {
    accounts: HashMap<ServiceId, AccountSandbox<S>>,
}

impl<S: HostStateProvider> Clone for AccountsSandboxMap<S> {
    fn clone(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
        }
    }
}

impl<S: HostStateProvider> Default for AccountsSandboxMap<S> {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }
}

impl<S: HostStateProvider> Deref for AccountsSandboxMap<S> {
    type Target = HashMap<ServiceId, AccountSandbox<S>>;

    fn deref(&self) -> &Self::Target {
        &self.accounts
    }
}

impl<S: HostStateProvider> DerefMut for AccountsSandboxMap<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.accounts
    }
}

impl<S: HostStateProvider> AccountsSandboxMap<S> {
    /// Initializes the service account sandbox state by copying the account metadata from the
    /// global state and initializing empty HashMap types for storage types.
    async fn ensure_account_sandbox_initialized(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if !self.contains_key(&service_id) && state_provider.account_exists(service_id).await? {
            self.insert(
                service_id,
                AccountSandbox::from_service_id(state_provider, service_id).await?,
            );
        }
        Ok(())
    }

    /// Returns `true` if the given service ID is already known, either in the accounts sandbox
    /// or in the global state. Even if the sandbox entry is marked for removed, returns `true`.
    pub async fn account_exists_anywhere(
        &self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<bool, PartialStateError> {
        if self.contains_key(&service_id) || state_provider.account_exists(service_id).await? {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns `true` only when the sandbox still has a live copy of the account:
    /// the entry exists and hasn’t been marked for removal, or it was newly added but
    /// not yet added to the global state.
    pub async fn account_exists_active(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<bool, PartialStateError> {
        if let Some(account_sandbox) = self.get_account_sandbox(state_provider, service_id).await? {
            if matches!(
                account_sandbox.metadata.entry.status,
                SandboxEntryStatus::Removed
            ) {
                // Account exists in the global state but removed from the sandbox
                Ok(false)
            } else {
                // Account exists in the global state and not removed from the sandbox,
                // or is the new account added into the sandbox but not created in the global state yet.
                Ok(true)
            }
        } else {
            // Account doesn't exist both in the global state and the sandbox
            Ok(false)
        }
    }

    pub async fn get_account_sandbox(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<&AccountSandbox<S>>, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_provider, service_id)
            .await?;
        Ok(self.get(&service_id))
    }

    pub async fn get_mut_account_sandbox(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountSandbox<S>>, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_provider, service_id)
            .await?;
        Ok(self.get_mut(&service_id))
    }

    /// Gets a reference to an `AccountMetadata` from the account sandbox.
    /// Returns `None` if the account doesn't exist in the global state or was removed from the
    /// partial state.
    pub async fn get_account_metadata(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<&AccountMetadata>, PartialStateError> {
        Ok(self
            .get_account_sandbox(state_provider, service_id)
            .await?
            .and_then(|sandbox| sandbox.metadata.as_ref()))
    }

    /// Gets a mutable reference to an `AccountMetadata` from the account sandbox.
    /// Returns `None` if the account doesn't exist in the global state or was removed from the
    /// partial state.
    pub async fn get_mut_account_metadata(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountMetadata>, PartialStateError> {
        Ok(self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .and_then(|sandbox| sandbox.metadata.as_mut()))
    }

    async fn get_account_metadata_clean(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<AccountMetadata>, PartialStateError> {
        let sandbox =
            if let Some(sandbox) = self.get_account_sandbox(state_provider, service_id).await? {
                sandbox
            } else {
                return Ok(None);
            };
        if let SandboxEntryStatus::Clean = sandbox.metadata.entry.status {
            Ok(sandbox.metadata.entry.value.clone())
        } else {
            Ok(sandbox.metadata.clean_snapshot.clone())
        }
    }

    pub async fn mark_account_metadata_updated(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if let Some(sandbox) = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
        {
            sandbox.metadata.mark_updated();
        }
        Ok(())
    }

    pub async fn mark_account_metadata_removed(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        if let Some(sandbox) = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
        {
            sandbox.metadata.mark_removed();
        }
        Ok(())
    }

    /// Retrieves service account code (preimage of the code hash)
    /// directly from the account preimage storage of the partial state.
    ///
    /// Used by `accumulate` PVM invocation where direct access to on-chain state is possible.
    pub async fn get_account_code(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Option<AccountCode>, PartialStateError> {
        let code_hash = {
            let Some(metadata) = self
                .get_account_metadata(state_provider.clone(), service_id)
                .await?
            else {
                tracing::warn!("Account not found. s={service_id}");
                return Ok(None);
            };
            metadata.code_hash.clone()
        };

        tracing::debug!("Code hash: {}", &code_hash.encode_hex());
        let code_preimage = self
            .get_account_preimages_entry(state_provider, service_id, &code_hash)
            .await?;
        Ok(code_preimage
            .map(|code| AccountCode::decode(&mut code.value.as_slice()))
            .transpose()?)
    }

    pub async fn update_account_footprints(
        &mut self,
        state_manager: Arc<S>,
        service_id: ServiceId,
        account_storage_usage_delta: AccountStorageUsageDelta,
    ) -> Result<(), PartialStateError> {
        let sandbox = self
            .get_mut_account_sandbox(state_manager.clone(), service_id)
            .await?
            .ok_or(PartialStateError::AccumulatorAccountNotInitialized(
                service_id,
            ))?;

        if let Some(metadata_mut) = sandbox.metadata.as_mut() {
            let updated = metadata_mut
                .update_footprints(AccountFootprintDelta::from(account_storage_usage_delta));
            if updated {
                sandbox.metadata.mark_updated()
            }
        }
        Ok(())
    }

    /// Attempts to retrieve a sandbox entry of type `T`
    /// from the map or the global state using the given key.
    ///
    /// The `map` is one of the account storage types stored in `AccountSandbox`, which stores storage
    /// entries wrapped with types that implement `SandboxEntryAccessor<T>` trait.
    /// This can represent state entry copied from the global state (state manager)
    /// or its mutated version (added, updated or removed) in the sandboxed environment.
    ///
    /// If an item of the given key is not found from the `map`, it attempts to load it from the global
    /// state by invoking `load_from_global` and then insert the found entry to the `map` if exists.
    async fn get_or_load_sandboxed_entry<K, V, T, F, Fut>(
        map: &mut HashMap<K, V>,
        key: &K,
        load_from_global: F,
    ) -> Result<Option<V>, PartialStateError>
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
            return Ok(Some(entry.clone()));
        }

        // If not found in the map, attempt to load it from the global state
        let entry_from_global = load_from_global().await?;
        if let Some(value) = entry_from_global {
            let clean_entry: V = SandboxEntryAccessor::from_clean(value);
            map.insert(key.clone(), clean_entry.clone());
            Ok(Some(clean_entry))
        } else {
            // Not found in the global state either
            Ok(None)
        }
    }

    pub async fn get_account_storage_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<AccountStorageEntryExt>, PartialStateError> {
        Ok(self
            .get_account_storage_entry_sandboxed(state_provider, service_id, storage_key)
            .await?
            .and_then(|entry| entry.get_cloned()))
    }

    async fn get_account_storage_entry_sandboxed(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<SandboxEntryVersioned<AccountStorageEntryExt>>, PartialStateError> {
        let Some(sandbox) = self
            .get_mut_account_sandbox(state_provider.clone(), service_id)
            .await?
        else {
            return Ok(None);
        };
        Self::get_or_load_sandboxed_entry(&mut sandbox.storage, storage_key, || async {
            Ok(state_provider
                .get_account_storage_entry(service_id, storage_key)
                .await?
                .map(|entry| AccountStorageEntryExt::from_entry(storage_key, entry)))
        })
        .await
    }

    async fn get_account_storage_entry_clean(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<AccountStorageEntryExt>, PartialStateError> {
        let sandbox_entry = if let Some(entry) = self
            .get_account_storage_entry_sandboxed(state_provider, service_id, storage_key)
            .await?
        {
            entry
        } else {
            return Ok(None);
        };
        if let SandboxEntryStatus::Clean = sandbox_entry.entry.status {
            Ok(sandbox_entry.entry.value)
        } else {
            Ok(sandbox_entry.clean_snapshot)
        }
    }

    /// Inserts a new storage entry to the account sandbox and returns the replaced entry, if exists.
    pub async fn insert_account_storage_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        storage_key: StorageKey,
        new_entry: AccountStorageEntryExt,
    ) -> Result<Option<AccountStorageEntryExt>, PartialStateError> {
        // Check the storage entry from the partial state and/or the global state
        let sandbox_entry_versioned = match self
            .get_account_storage_entry_clean(state_provider.clone(), service_id, &storage_key)
            .await?
        {
            Some(clean) => SandboxEntryVersioned::new_updated(new_entry, clean),
            None => SandboxEntryVersioned::new_added(new_entry),
        };

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        Ok(sandbox
            .storage
            .insert(storage_key, sandbox_entry_versioned)
            .and_then(|replaced| replaced.get_cloned()))
    }

    /// Removes a storage entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_storage_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        storage_key: StorageKey,
    ) -> Result<Option<AccountStorageEntryExt>, PartialStateError> {
        // Lookup the state entry from both the sandbox and the global state.
        //
        // In order for the entry to be safely removed, state entry with the given state key
        // must exist either in the sandbox or the global state.
        if self
            .get_account_storage_entry(state_provider.clone(), service_id, &storage_key)
            .await?
            .is_none()
        {
            // Attempted to remove an entry not found in either the sandbox or the global state
            // Note: should not throw an error
            return Ok(None);
        }

        // Lookup the state entry from the global state (or clean snapshot) to determine the final entry status.
        //
        // If the entry exists in the global state (or clean snapshot), the new entry should be
        // marked as `Remove`d, since the operation is effectively attempting to mark the entry as
        // removed in the sandbox.
        // Otherwise, the entry should be removed from the sandbox since the operation is removing
        // entry that is added during the accumulation, only existing in the sandbox.
        let maybe_clean_entry = self
            .get_account_storage_entry_clean(state_provider.clone(), service_id, &storage_key)
            .await?;

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        match maybe_clean_entry {
            Some(clean) => {
                // Entry with the key already exists in the global state
                let entry = SandboxEntryVersioned::new_removed(clean);
                Ok(sandbox
                    .storage
                    .insert(storage_key, entry)
                    .and_then(|removed| removed.get_cloned()))
            }
            None => {
                sandbox.storage.remove(&storage_key);
                Ok(None)
            }
        }
    }

    pub async fn get_account_preimages_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        Ok(self
            .get_account_preimages_entry_sandboxed(state_provider, service_id, preimages_key)
            .await?
            .and_then(|entry| entry.get_cloned()))
    }

    async fn get_account_preimages_entry_sandboxed(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<SandboxEntryVersioned<AccountPreimagesEntry>>, PartialStateError> {
        let Some(sandbox) = self
            .get_mut_account_sandbox(state_provider.clone(), service_id)
            .await?
        else {
            return Ok(None);
        };

        Self::get_or_load_sandboxed_entry(&mut sandbox.preimages, preimages_key, || {
            state_provider.get_account_preimages_entry(service_id, preimages_key)
        })
        .await
    }

    async fn get_account_preimages_entry_clean(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let sandbox_entry = if let Some(entry) = self
            .get_account_preimages_entry_sandboxed(state_provider, service_id, preimages_key)
            .await?
        {
            entry
        } else {
            return Ok(None);
        };
        if let SandboxEntryStatus::Clean = sandbox_entry.entry.status {
            Ok(sandbox_entry.entry.value)
        } else {
            Ok(sandbox_entry.clean_snapshot)
        }
    }

    /// Inserts a new preimages entry to the account sandbox and returns the replaced entry, if exists.
    pub async fn insert_account_preimages_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        preimages_key: PreimagesKey,
        new_entry: AccountPreimagesEntry,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        // Check the preimages entry from the partial state and/or the global state
        let sandbox_entry_versioned = match self
            .get_account_preimages_entry_clean(state_provider.clone(), service_id, &preimages_key)
            .await?
        {
            Some(clean) => SandboxEntryVersioned::new_updated(new_entry, clean),
            None => SandboxEntryVersioned::new_added(new_entry),
        };

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        Ok(sandbox
            .preimages
            .insert(preimages_key, sandbox_entry_versioned)
            .and_then(|replaced| replaced.get_cloned()))
    }

    /// Removes a preimages entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_preimages_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        preimages_key: PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        // Lookup the state entry from both the sandbox and the global state.
        //
        // In order for the entry to be safely removed, state entry with the given state key
        // must exist either in the sandbox or the global state.
        if self
            .get_account_preimages_entry(state_provider.clone(), service_id, &preimages_key)
            .await?
            .is_none()
        {
            // Attempted to remove an entry not found in either the sandbox or the global state
            // Note: should not throw an error
            return Ok(None);
        }

        // Lookup the state entry from the global state (or clean snapshot) to determine the final entry status.
        //
        // If the entry exists in the global state (or clean snapshot), the new entry should be
        // marked as `Remove`d, since the operation is effectively attempting to mark the entry as
        // removed in the sandbox.
        // Otherwise, the entry should be removed from the sandbox since the operation is removing
        // entry that is added during the accumulation, only existing in the sandbox.
        let maybe_clean_entry = self
            .get_account_preimages_entry_clean(state_provider.clone(), service_id, &preimages_key)
            .await?;

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        match maybe_clean_entry {
            Some(clean) => {
                // Entry with the key already exists in the global state
                let entry = SandboxEntryVersioned::new_removed(clean);
                Ok(sandbox
                    .preimages
                    .insert(preimages_key, entry)
                    .and_then(|removed| removed.get_cloned()))
            }
            None => {
                sandbox.preimages.remove(&preimages_key);
                Ok(None)
            }
        }
    }

    pub async fn get_account_lookups_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_storage_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        Ok(self
            .get_account_lookups_entry_sandboxed(state_provider, service_id, lookups_storage_key)
            .await?
            .and_then(|entry| entry.get_cloned()))
    }

    async fn get_account_lookups_entry_sandboxed(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_storage_key: &LookupsKey,
    ) -> Result<Option<SandboxEntryVersioned<AccountLookupsEntryExt>>, PartialStateError> {
        let Some(sandbox) = self
            .get_mut_account_sandbox(state_provider.clone(), service_id)
            .await?
        else {
            return Ok(None);
        };

        Self::get_or_load_sandboxed_entry(&mut sandbox.lookups, lookups_storage_key, || async {
            Ok(state_provider
                .get_account_lookups_entry(service_id, lookups_storage_key)
                .await?
                .map(|entry| {
                    AccountLookupsEntryExt::from_entry(lookups_storage_key.clone(), entry)
                }))
        })
        .await
    }

    async fn get_account_lookups_entry_clean(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_storage_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        let sandbox_entry = if let Some(entry) = self
            .get_account_lookups_entry_sandboxed(state_provider, service_id, lookups_storage_key)
            .await?
        {
            entry
        } else {
            return Ok(None);
        };
        if let SandboxEntryStatus::Clean = sandbox_entry.entry.status {
            Ok(sandbox_entry.entry.value)
        } else {
            Ok(sandbox_entry.clean_snapshot)
        }
    }

    /// Inserts a new lookups entry to the account sandbox and returns the replaced entry, if exists.
    pub async fn insert_account_lookups_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
        new_entry: AccountLookupsEntryExt,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        // Check the storage entry from the partial state and/or the global state
        let sandbox_entry_versioned = match self
            .get_account_lookups_entry_clean(state_provider.clone(), service_id, &lookups_key)
            .await?
        {
            Some(clean) => SandboxEntryVersioned::new_updated(new_entry, clean),
            None => SandboxEntryVersioned::new_added(new_entry),
        };

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        Ok(sandbox
            .lookups
            .insert(lookups_key, sandbox_entry_versioned)
            .and_then(|replaced| replaced.get_cloned()))
    }

    /// Removes a lookups entry from the account sandbox and returns the removed entry.
    /// If the entry didn't exist, returns `None`.
    pub async fn remove_account_lookups_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
    ) -> Result<Option<AccountLookupsEntryExt>, PartialStateError> {
        // Lookup the state entry from both the sandbox and the global state.
        //
        // In order for the entry to be safely removed, state entry with the given state key
        // must exist either in the sandbox or the global state.
        if self
            .get_account_lookups_entry(state_provider.clone(), service_id, &lookups_key)
            .await?
            .is_none()
        {
            // Attempted to remove an entry not found in either the sandbox or the global state
            // Note: should not throw an error
            return Ok(None);
        }

        // Lookup the state entry from the global state (or clean snapshot) to determine the final entry status.
        //
        // If the entry exists in the global state (or clean snapshot), the new entry should be
        // marked as `Remove`d, since the operation is effectively attempting to mark the entry as
        // removed in the sandbox.
        // Otherwise, the entry should be removed from the sandbox since the operation is removing
        // entry that is added during the accumulation, only existing in the sandbox.
        let maybe_clean_entry = self
            .get_account_lookups_entry_clean(state_provider.clone(), service_id, &lookups_key)
            .await?;

        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        match maybe_clean_entry {
            Some(clean) => {
                // Entry with the key already exists in the global state
                let entry = SandboxEntryVersioned::new_removed(clean);
                Ok(sandbox
                    .lookups
                    .insert(lookups_key, entry)
                    .and_then(|removed| removed.get_cloned()))
            }
            None => {
                sandbox.lookups.remove(&lookups_key);
                Ok(None)
            }
        }
    }

    /// Pushes a new timeslot to the lookups entry value sequence and returns
    /// the updated lookups entry.
    /// Returns `None` if such lookups entry is not found.
    pub async fn push_timeslot_to_account_lookups_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
        timeslot: Timeslot,
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let Some(mut lookups_entry) = self
            .get_account_lookups_entry(state_provider.clone(), service_id, &lookups_key)
            .await?
        else {
            return Ok(None);
        };
        lookups_entry.value.try_push(timeslot)?;

        self.insert_account_lookups_entry(
            state_provider,
            service_id,
            lookups_key,
            lookups_entry.clone(),
        )
        .await?;
        Ok(Some(lookups_entry.entry))
    }

    /// Extends timeslots vector to the lookups entry and returns the updated lookups entry.
    /// Returns `None` if such lookups entry is not found.
    pub async fn extend_timeslots_to_account_lookups_entry(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
        timeslots: Vec<Timeslot>,
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let Some(mut lookups_entry) = self
            .get_account_lookups_entry(state_provider.clone(), service_id, &lookups_key)
            .await?
        else {
            return Ok(None);
        };
        lookups_entry.value.try_extend(timeslots)?;
        self.insert_account_lookups_entry(
            state_provider,
            service_id,
            lookups_key,
            lookups_entry.clone(),
        )
        .await?;
        Ok(Some(lookups_entry.entry))
    }

    pub async fn drain_account_lookups_entry_timeslots(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        lookups_key: LookupsKey,
    ) -> Result<bool, PartialStateError> {
        let Some(mut lookups_entry) = self
            .get_account_lookups_entry(state_provider.clone(), service_id, &lookups_key)
            .await?
        else {
            return Ok(false);
        };
        lookups_entry.value = AccountLookupsEntryTimeslots::new();
        self.insert_account_lookups_entry(state_provider, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(true)
    }

    pub async fn eject_account(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        one_last_lookups_key: LookupsKey,
    ) -> Result<(), PartialStateError> {
        // Lookup the account metadata entry from both the sandbox and the global state.
        //
        // In order for the entry to be safely removed, state entry with the given state key
        // must exist either in the sandbox or the global state.
        if self
            .get_account_metadata(state_provider.clone(), service_id)
            .await?
            .is_none()
        {
            // Attempted to remove an entry not found in either the sandbox or the global state
            unreachable!("Account being ejected not found from the global state; this case should be handled by the host function");
        }

        // Lookup the state entry from the global state (or clean snapshot) to determine the final entry status.
        //
        // If the entry exists in the global state (or clean snapshot), the new entry should be
        // marked as `Remove`d, since the operation is effectively attempting to mark the entry as
        // removed in the sandbox.
        // Otherwise, the entry should be removed from the sandbox since the operation is removing
        // entry that is added during the accumulation, only existing in the sandbox.
        let Some(clean) = self
            .get_account_metadata_clean(state_provider.clone(), service_id)
            .await?
        else {
            // Removing account metadata entry that only exists in the sandbox.
            self.remove(&service_id);
            return Ok(());
        };

        // Remove the last lookups and preimage entries for the account.
        // Since the `EJECT` host function requires that all storage entries associated with the
        // ejecting account must be removed except for the last lookup entry, removing
        // these two entries is sufficient.
        // There's no need to iterate through all storage items (actually impossible to do so).
        self.remove_account_preimages_entry(
            state_provider.clone(),
            service_id,
            one_last_lookups_key.0.clone(),
        )
        .await?;
        self.remove_account_lookups_entry(state_provider.clone(), service_id, one_last_lookups_key)
            .await?;

        // Entry with the key already exists in the global state
        let entry = SandboxEntryVersioned::new_removed(clean);
        let sandbox = self
            .get_mut_account_sandbox(state_provider, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState(
                service_id,
            ))?;

        sandbox.metadata = entry;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AssignServicesPartialState {
    /// The latest state copied from the beginning of the current parallel accumulation round.
    pub last_confirmed: AssignServices,
    /// The changed assigner service ids by the accumulation of the manager service within the
    /// current parallel accumulation round. This change is prioritized over the `change_by_self`.
    pub change_by_manager: Option<AssignServices>,
    /// The changed assigner service ids by the assigner services themselves within the current
    /// parallel accumulation round.
    pub change_by_self: HashMap<CoreIndex, ServiceId>,
}

impl AssignServicesPartialState {
    pub fn new(assign_services: AssignServices) -> Self {
        Self {
            last_confirmed: assign_services,
            change_by_manager: None,
            change_by_self: HashMap::new(),
        }
    }

    /// Merges changes of the `AssignServices` state from the `other` partial state into `self`.
    pub fn merge_changes_from(
        &mut self,
        other: &AssignServicesPartialState,
    ) -> Result<(), PartialStateError> {
        if let Some(assigners_by_manager) = &other.change_by_manager {
            self.change_by_manager = Some(assigners_by_manager.clone());
            return Ok(());
        }

        for (&core_idx, &assigner_by_self) in &other.change_by_self {
            let original = *other
                .last_confirmed
                .get(core_idx as usize)
                .ok_or(PartialStateError::CoreIndexOutOfBounds(core_idx))?;
            if assigner_by_self != original {
                self.change_by_self.insert(core_idx, assigner_by_self);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DesignateServicePartialState {
    /// The latest state copied from the beginning of the current parallel accumulation round.
    pub last_confirmed: ServiceId,
    /// The changed designate service id by the accumulation of the manager service within the
    /// current parallel accumulation round. This change is prioritized over the `change_by_self`.
    pub change_by_manager: Option<ServiceId>,
    /// The changed designate service id by the designate service itself within the current
    /// parallel accumulation round.
    pub change_by_self: Option<ServiceId>,
}

impl DesignateServicePartialState {
    pub fn new(designate_service: ServiceId) -> Self {
        Self {
            last_confirmed: designate_service,
            change_by_self: None,
            change_by_manager: None,
        }
    }

    /// Merges changes of the designate service from the `other` partial state into `self`.
    pub fn merge_changes_from(&mut self, other: &DesignateServicePartialState) {
        let original = other.last_confirmed;
        if let Some(designate_by_manager) = other.change_by_manager {
            if designate_by_manager != original {
                self.change_by_manager = Some(designate_by_manager);
                return;
            }
        }

        if let Some(designate_by_self) = other.change_by_self {
            if designate_by_self != original {
                self.change_by_self = Some(designate_by_self);
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistrarServicePartialState {
    /// The latest state copied from the beginning of the current parallel accumulation round.
    pub last_confirmed: ServiceId,
    /// The changed registrar service id by the accumulation of the manager service within the
    /// current parallel accumulation round. This change is prioritized over the `change_by_self`.
    pub change_by_manager: Option<ServiceId>,
    /// The changed registrar service id by the registrar service itself within the current
    /// parallel accumulation round.
    pub change_by_self: Option<ServiceId>,
}

impl RegistrarServicePartialState {
    pub fn new(registrar_service: ServiceId) -> Self {
        Self {
            last_confirmed: registrar_service,
            change_by_self: None,
            change_by_manager: None,
        }
    }

    /// Merges changes of the registrar service from the `other` partial state into `self`.
    pub fn merge_changes_from(&mut self, other: &RegistrarServicePartialState) {
        let original = other.last_confirmed;
        if let Some(registrar_by_manager) = other.change_by_manager {
            if registrar_by_manager != original {
                self.change_by_manager = Some(registrar_by_manager);
                return;
            }
        }

        if let Some(registrar_by_self) = other.change_by_self {
            if registrar_by_self != original {
                self.change_by_self = Some(registrar_by_self);
            }
        }
    }
}

/// Represents a mutable copy of a subset of the global state used during the accumulation process.
///
/// This provides a sandboxed environment for performing state mutations safely, yielding the final
/// change set of the state on success and discarding the mutations on failure.
pub struct AccumulatePartialState<S: HostStateProvider> {
    /// **`d`**: Sandboxed copy of service accounts states
    pub accounts_sandbox: AccountsSandboxMap<S>,
    /// **`i`**: New allocation of `StagingSet` after accumulation
    pub new_staging_set: Option<StagingSet>,
    /// **`q`**: Sandboxed copy of auth queue
    pub auth_queue: AuthQueue,
    /// `m`: Sandboxed copy of privileged manager service id
    pub manager_service: ServiceId,
    /// **`a`**: Sandboxed copy of privileged assign service ids
    pub assign_services: AssignServicesPartialState,
    /// `v`: Sandboxed copy of privileged designate service id
    pub designate_service: DesignateServicePartialState,
    /// `r`: Sandboxed copy of privileged registrar service id
    pub registrar_service: RegistrarServicePartialState,
    /// **`z`**: Sandboxed copy of privileged always-accumulate services
    pub always_accumulate_services: AlwaysAccumulateServices,
}

impl<S: HostStateProvider> Clone for AccumulatePartialState<S> {
    fn clone(&self) -> Self {
        Self {
            accounts_sandbox: self.accounts_sandbox.clone(),
            new_staging_set: self.new_staging_set.clone(),
            auth_queue: self.auth_queue.clone(),
            manager_service: self.manager_service,
            assign_services: self.assign_services.clone(),
            designate_service: self.designate_service.clone(),
            registrar_service: self.registrar_service.clone(),
            always_accumulate_services: self.always_accumulate_services.clone(),
        }
    }
}

impl<S: HostStateProvider> Default for AccumulatePartialState<S> {
    fn default() -> Self {
        Self {
            accounts_sandbox: AccountsSandboxMap::default(),
            new_staging_set: None,
            auth_queue: AuthQueue::default(),
            manager_service: ServiceId::default(),
            assign_services: AssignServicesPartialState::default(),
            designate_service: DesignateServicePartialState::default(),
            registrar_service: RegistrarServicePartialState::default(),
            always_accumulate_services: AlwaysAccumulateServices::default(),
        }
    }
}

impl<S: HostStateProvider> AccumulatePartialState<S> {
    /// Initializes `AccumulatePartialState`.
    pub async fn new(state_provider: Arc<S>) -> Result<Self, PartialStateError> {
        let auth_queue = state_provider.get_auth_queue().await?;
        let PrivilegedServices {
            manager_service,
            assign_services,
            designate_service,
            registrar_service,
            always_accumulate_services,
        } = state_provider.get_privileged_services().await?;
        Ok(Self {
            accounts_sandbox: AccountsSandboxMap::default(),
            new_staging_set: None,
            auth_queue,
            manager_service,
            assign_services: AssignServicesPartialState::new(assign_services),
            designate_service: DesignateServicePartialState::new(designate_service),
            registrar_service: RegistrarServicePartialState::new(registrar_service),
            always_accumulate_services,
        })
    }

    /// Initializes `AccumulatePartialState` with the accumulator service account sandbox entry.
    pub async fn new_from_service_id(
        state_provider: Arc<S>,
        service_id: ServiceId,
    ) -> Result<Self, PartialStateError> {
        let mut accounts_sandbox = HashMap::new();
        let account_sandbox =
            AccountSandbox::from_service_id(state_provider.clone(), service_id).await?;
        accounts_sandbox.insert(service_id, account_sandbox);

        let auth_queue = state_provider.get_auth_queue().await?;
        let PrivilegedServices {
            manager_service,
            assign_services,
            designate_service,
            registrar_service,
            always_accumulate_services,
        } = state_provider.get_privileged_services().await?;

        Ok(Self {
            accounts_sandbox: AccountsSandboxMap {
                accounts: accounts_sandbox,
            },
            new_staging_set: None,
            auth_queue,
            manager_service,
            assign_services: AssignServicesPartialState::new(assign_services),
            designate_service: DesignateServicePartialState::new(designate_service),
            registrar_service: RegistrarServicePartialState::new(registrar_service),
            always_accumulate_services,
        })
    }

    pub async fn subtract_account_balance(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        amount: Balance,
    ) -> Result<(), PartialStateError> {
        let account_metadata = self
            .accounts_sandbox
            .get_mut_account_metadata(state_provider.clone(), service_id)
            .await?
            .ok_or(PartialStateError::AccumulatorAccountNotInitialized(
                service_id,
            ))?;

        let subtracted_amount = account_metadata
            .balance
            .checked_sub(amount)
            .ok_or(PartialStateError::AccountBalanceUnderflow(service_id))?;
        account_metadata.balance = subtracted_amount;
        self.accounts_sandbox
            .mark_account_metadata_updated(state_provider, service_id)
            .await?;
        Ok(())
    }

    pub async fn add_account_balance(
        &mut self,
        state_provider: Arc<S>,
        service_id: ServiceId,
        amount: Balance,
    ) -> Result<(), PartialStateError> {
        let account_metadata = self
            .accounts_sandbox
            .get_mut_account_metadata(state_provider.clone(), service_id)
            .await?
            .ok_or(PartialStateError::AccountBalanceOverflow(service_id))?;

        let added_amount = account_metadata.balance.checked_add(amount).ok_or(
            PartialStateError::AccumulatorAccountNotInitialized(service_id),
        )?;
        account_metadata.balance = added_amount;
        self.accounts_sandbox
            .mark_account_metadata_updated(state_provider, service_id)
            .await?;
        Ok(())
    }

    /// Clears changes marked for privileged services. This should be invoked by
    /// the union partial state only - which holds the merged and finalized effects of
    /// multiple single-service accumulations within a parallel accumulation.
    pub fn clear_privileged_services_changes(&mut self) {
        self.assign_services.change_by_manager = None;
        self.assign_services.change_by_self = HashMap::new();
        self.designate_service.change_by_manager = None;
        self.designate_service.change_by_self = None;
        self.registrar_service.change_by_manager = None;
        self.registrar_service.change_by_self = None;
    }
}
