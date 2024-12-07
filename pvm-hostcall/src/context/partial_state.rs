use rjam_common::{Address, Hash32};
use rjam_state::{StateManager, StateManagerError};
use rjam_types::state::{
    authorizer::AuthQueue,
    services::{
        AccountLookupsEntry, AccountMetadata, AccountPreimagesEntry, AccountStorageEntry,
        PVMContextState, PrivilegedServices,
    },
    validators::StagingSet,
};
use std::{collections::HashMap, hash::Hash};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PartialStateError {
    #[error("Account not found from the global state")]
    AccountNotFoundFromGlobalState,
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

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

#[derive(Clone)]
pub struct ServiceAccountSandbox {
    pub metadata: StateView<AccountMetadata>,
    pub storage: HashMap<Hash32, StateView<AccountStorageEntry>>,
    pub preimages: HashMap<Hash32, StateView<AccountPreimagesEntry>>,
    pub lookups: HashMap<(Hash32, u32), StateView<AccountLookupsEntry>>,
}

impl ServiceAccountSandbox {
    fn new_with_account_metadata(account_metadata: AccountMetadata) -> Self {
        Self {
            metadata: StateView::Entry(account_metadata),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AccumulatePartialState {
    pub service_accounts_sandbox: HashMap<Address, ServiceAccountSandbox>,
    pub new_staging_set: Option<StagingSet>,
    pub new_auth_queue: Option<AuthQueue>,
    pub new_privileges: Option<PrivilegedServices>,
}

impl AccumulatePartialState {
    // TODO: add `new_from_address` method

    /// Initializes the service account sandbox state by copying the account metadata from the
    /// global state and initializing empty HashMap types for storage types.
    #[allow(clippy::map_entry)]
    fn ensure_account_sandbox_initialized(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<(), PartialStateError> {
        if !self.service_accounts_sandbox.contains_key(&address) {
            let metadata = state_manager
                .get_account_metadata(address)?
                .ok_or(PartialStateError::AccountNotFoundFromGlobalState)?;

            self.service_accounts_sandbox.insert(
                address,
                ServiceAccountSandbox::new_with_account_metadata(metadata),
            );
        }
        Ok(())
    }

    fn get_account_sandbox(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<&ServiceAccountSandbox, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_manager, address)?;
        self.service_accounts_sandbox
            .get(&address)
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)
    }

    fn get_mut_account_sandbox(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<&mut ServiceAccountSandbox, PartialStateError> {
        self.ensure_account_sandbox_initialized(state_manager, address)?;
        self.service_accounts_sandbox
            .get_mut(&address)
            .ok_or(PartialStateError::AccountNotFoundFromGlobalState)
    }

    pub fn get_account_metadata(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<Option<&AccountMetadata>, PartialStateError> {
        Ok(self
            .get_account_sandbox(state_manager, address)?
            .metadata
            .as_ref())
    }

    pub fn get_mut_account_metadata(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<Option<&mut AccountMetadata>, PartialStateError> {
        Ok(self
            .get_mut_account_sandbox(state_manager, address)?
            .metadata
            .as_mut())
    }

    /// Attempts to retrieve an entry of type `T` from the provided map using the given key.
    ///
    /// The map stores entries as `StateView<T>`, which can represent existing (`Entry`) or removed entries.
    /// If the entry is present as `Entry(...)`, its cloned value is returned.
    /// If it is `Removed` or not found, this function attempts to load it
    /// from the global state by invoking `load_from_global`.
    ///
    /// - If `load_from_global` returns `Some(value)`, that value is inserted into the map as `Entry(value)`
    ///   and then returned.
    /// - If it returns `None`, the function concludes that the entry does not exist globally, and returns `None`.
    ///
    /// In summary, this function returns:
    /// - `Some(T)` if the entry is found in the map or successfully loaded from the global state.
    /// - `None` if the entry is neither found in the map nor retrievable from the global state.
    fn get_or_load_entry<K, T, F>(
        map: &mut HashMap<K, StateView<T>>,
        key: &K,
        load_from_global: F,
    ) -> Result<Option<T>, PartialStateError>
    where
        K: Eq + Hash + Clone,
        T: PVMContextState + Clone,
        F: FnOnce() -> Result<Option<T>, StateManagerError>,
    {
        // Check if the entry is already in the map of the account sandbox.
        // If the entry is `Remove` variant of the `StateView`, None is returned
        {
            if let Some(view) = map.get(key) {
                return Ok(view.cloned());
            }
        }

        // If not found in the map, attempt to load it from the global state
        let entry_from_global = load_from_global()?;
        if let Some(value) = entry_from_global {
            map.insert(key.clone(), StateView::Entry(value));
            Ok(map.get(key).and_then(|view| view.cloned()))
        } else {
            // Not found in the global state either
            Ok(None)
        }
    }

    pub fn get_or_load_account_storage_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        storage_key: &Hash32,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        Self::get_or_load_entry(&mut account_sandbox.storage, storage_key, || {
            state_manager.get_account_storage_entry(address, storage_key)
        })
    }

    pub fn insert_account_storage_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        storage_key: Hash32,
        new_entry: AccountStorageEntry,
    ) -> Result<Option<AccountStorageEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        let replaced = account_sandbox
            .storage
            .insert(storage_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }

    pub fn get_or_load_account_preimages_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        preimages_storage_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        Self::get_or_load_entry(
            &mut account_sandbox.preimages,
            preimages_storage_key,
            || state_manager.get_account_preimages_entry(address, preimages_storage_key),
        )
    }

    pub fn insert_account_preimages_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        preimages_storage_key: Hash32,
        new_entry: AccountPreimagesEntry,
    ) -> Result<Option<AccountPreimagesEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        let replaced = account_sandbox
            .preimages
            .insert(preimages_storage_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }

    pub fn get_or_load_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        lookups_storage_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        Self::get_or_load_entry(&mut account_sandbox.lookups, lookups_storage_key, || {
            state_manager.get_account_lookups_entry(address, lookups_storage_key)
        })
    }

    pub fn insert_account_lookups_entry(
        &mut self,
        state_manager: &StateManager,
        address: Address,
        lookups_storage_key: (Hash32, u32),
        new_entry: AccountLookupsEntry,
    ) -> Result<Option<AccountLookupsEntry>, PartialStateError> {
        let account_sandbox = self.get_mut_account_sandbox(state_manager, address)?;
        let replaced = account_sandbox
            .lookups
            .insert(lookups_storage_key, StateView::Entry(new_entry));

        if let Some(replaced) = replaced {
            Ok(replaced.cloned())
        } else {
            Ok(None)
        }
    }
}
