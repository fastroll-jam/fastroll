use rjam_common::{Hash32, ServiceId};
use rjam_pvm_core::types::error::PartialStateError;
use rjam_state::{error::StateManagerError, StateManager};
use rjam_types::state::*;
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    ops::{Deref, DerefMut},
};

/// Represents a sandboxed copy of an account state for use in hostcall execution contexts.
/// The account state may originate from the global state or be created/removed within the
/// execution context.
///
/// # Variants
/// - `Entry(T)`:
///   Represents an account state that is either:
///   - Copied from the global state and potentially modified during execution.
///   - Created during the execution context without a prior global state reference.
/// - `Removed`:
///   Represents an account state that was initially copied from the global state but
///   was subsequently removed during execution.
#[derive(Clone)]
pub enum StateView<T: PVMContextState> {
    Entry(T),
    Removed,
}

impl<T> StateView<T>
where
    T: PVMContextState + Clone,
{
    fn cloned(&self) -> Option<T> {
        match self {
            Self::Entry(a) => Some(a.clone()),
            Self::Removed => None,
        }
    }

    fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Entry(a) => Some(a),
            Self::Removed => None,
        }
    }

    fn as_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Entry(a) => Some(a),
            Self::Removed => None,
        }
    }
}

/// Represents a service account, including its metadata and associated storage entries.
///
/// Primarily used in the `accumulate` and `on_transfer` context for state mutations involving service accounts.
/// The global state serialization doesn't require the service metadata and storage entries to be
/// stored together, which makes this type to be specific to the accumulation process.
///
/// Represents type `A` of the GP.
#[derive(Clone)]
pub struct AccountSandbox {
    pub metadata: StateView<AccountMetadata>,
    pub storage: HashMap<Hash32, StateView<AccountStorageEntry>>,
    pub preimages: HashMap<Hash32, StateView<AccountPreimagesEntry>>,
    pub lookups: HashMap<(Hash32, u32), StateView<AccountLookupsEntry>>,
}

impl AccountSandbox {
    pub async fn from_service_id(
        state_manager: &StateManager,
        service_id: ServiceId,
    ) -> Result<Self, PartialStateError> {
        let account_metadata = state_manager
            .get_account_metadata(service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        Ok(Self {
            metadata: StateView::Entry(account_metadata),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
        })
    }
}

/// Represents a collection of service account sandboxes
#[derive(Clone, Default)]
pub struct AccountsSandboxMap {
    pub accounts: HashMap<ServiceId, AccountSandbox>,
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
        state_manager: &StateManager,
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
        state_manager: &StateManager,
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
        state_manager: &StateManager,
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

    pub async fn get_account_metadata(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
    ) -> Result<Option<&AccountMetadata>, PartialStateError> {
        // Returns `None` if the account doesn't exist in the global state or was removed from the
        // partial state.
        match self.get_account_sandbox(state_manager, service_id).await? {
            Some(sandbox) => Ok(sandbox.metadata.as_ref()),
            None => Ok(None),
        }
    }

    pub async fn get_mut_account_metadata(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
    ) -> Result<Option<&mut AccountMetadata>, PartialStateError> {
        // Returns `None` if the account doesn't exist in the global state or was removed from the
        // partial state.
        match self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
        {
            Some(sandbox) => Ok(sandbox.metadata.as_mut()),
            None => Ok(None),
        }
    }

    /// Attempts to retrieve an entry of type `T` from the provided map or the global state using the given key.
    ///
    /// The map stores entries as `StateView<T>`, which can represent existing or removed entries of
    /// sandboxed account state.
    ///
    /// If the entry is present as `Entry(T)`, returns its cloned value. Otherwise, returns `None`.
    ///
    /// If an item with the given key is not found from the map, it attempts to load the corresponding
    /// item from the global state by invoking `load_from_global`.
    ///
    /// - If `load_from_global` returns `Some(T)`, that value is inserted into the map as `Entry(T)`
    ///   and then returned.
    /// - If it returns `None`, the function concludes that the entry does not exist globally, and returns `None`.
    ///
    /// In summary, this function returns:
    /// - `Some(T)` if the entry is found in the map or successfully loaded from the global state.
    /// - `None` if the entry is neither found in the map nor retrievable from the global state.
    async fn get_or_load_entry<K, T, F, Fut>(
        map: &mut HashMap<K, StateView<T>>,
        key: &K,
        load_from_global: F,
    ) -> Result<Option<T>, PartialStateError>
    where
        K: Eq + Hash + Clone,
        T: PVMContextState + Clone,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<T>, StateManagerError>>,
    {
        // Check if the entry is already in the map of the account sandbox.
        // If the entry is `Removed` variant of the `StateView`, `None` is returned

        if let Some(view) = map.get(key) {
            return Ok(view.cloned());
        }

        // If not found in the map, attempt to load it from the global state
        let entry_from_global = load_from_global().await?;
        if let Some(value) = entry_from_global {
            map.insert(key.clone(), StateView::Entry(value));
            Ok(map.get(key).and_then(|view| view.cloned()))
        } else {
            // Not found in the global state either
            Ok(None)
        }
    }

    pub async fn get_or_load_account_storage_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        storage_key: &Hash32,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?;
        match account_sandbox {
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

    pub async fn insert_account_storage_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        storage_key: Hash32,
        new_entry: AccountStorageEntry,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let replaced = account_sandbox
            .storage
            .insert(storage_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn remove_account_storage_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        storage_key: Hash32,
    ) -> Result<(), PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        account_sandbox
            .storage
            .insert(storage_key, StateView::Removed);
        Ok(())
    }

    pub async fn get_or_load_account_preimages_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?;
        match account_sandbox {
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

    pub async fn insert_account_preimages_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        preimages_key: Hash32,
        new_entry: AccountPreimagesEntry,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let replaced = account_sandbox
            .preimages
            .insert(preimages_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn remove_account_preimages_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        preimages_key: Hash32,
    ) -> Result<(), PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        account_sandbox
            .preimages
            .insert(preimages_key, StateView::Removed);
        Ok(())
    }

    pub async fn get_or_load_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_storage_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?;
        match account_sandbox {
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

    pub async fn insert_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        new_entry: AccountLookupsEntry,
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        let replaced = account_sandbox
            .lookups
            .insert(lookups_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn remove_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
    ) -> Result<(), PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        account_sandbox
            .lookups
            .insert(lookups_key, StateView::Removed);
        Ok(())
    }

    /// Returns the length of the timeslot vector after appending a new entry.
    /// Returns None if such lookups entry is not found.
    pub async fn push_timeslot_to_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        timeslot: Timeslot,
    ) -> Result<Option<usize>, PartialStateError> {
        let lookups_entry = self
            .get_or_load_account_lookups_entry(state_manager, service_id, &lookups_key)
            .await?;
        if lookups_entry.is_none() {
            return Ok(None);
        }
        let mut lookups_entry = lookups_entry.unwrap();
        lookups_entry.value.push(timeslot);

        let new_timeslot_vec_len = lookups_entry.value.len();
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(Some(new_timeslot_vec_len))
    }

    pub async fn extend_timeslots_to_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
        timeslots: Vec<Timeslot>,
    ) -> Result<Option<usize>, PartialStateError> {
        let lookups_entry = self
            .get_or_load_account_lookups_entry(state_manager, service_id, &lookups_key)
            .await?;
        if lookups_entry.is_none() {
            return Ok(None);
        }
        let mut lookups_entry = lookups_entry.unwrap();
        lookups_entry.value.extend(timeslots);

        let new_timeslot_vec_len = lookups_entry.value.len();
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(Some(new_timeslot_vec_len))
    }

    pub async fn drain_account_lookups_entry_timeslots(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
        lookups_key: (Hash32, u32),
    ) -> Result<bool, PartialStateError> {
        let lookups_entry = self
            .get_or_load_account_lookups_entry(state_manager, service_id, &lookups_key)
            .await?;
        if lookups_entry.is_none() {
            return Ok(false);
        }
        let mut lookups_entry = lookups_entry.unwrap();
        lookups_entry.value = vec![];
        self.insert_account_lookups_entry(state_manager, service_id, lookups_key, lookups_entry)
            .await?;
        Ok(true)
    }

    pub async fn eject_account(
        &mut self,
        state_manager: &StateManager,
        service_id: ServiceId,
    ) -> Result<(), PartialStateError> {
        let account_sandbox = self
            .get_mut_account_sandbox(state_manager, service_id)
            .await?
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;
        account_sandbox.metadata = StateView::Removed;

        // Mark all storage entries associated with the service_id as removed.
        account_sandbox
            .storage
            .values_mut()
            .for_each(|v| *v = StateView::Removed);
        account_sandbox
            .preimages
            .values_mut()
            .for_each(|v| *v = StateView::Removed);
        account_sandbox
            .lookups
            .values_mut()
            .for_each(|v| *v = StateView::Removed);

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
        state_manager: &StateManager,
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
