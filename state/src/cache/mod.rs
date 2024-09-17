use jam_common::Hash32;
use jam_types::state::{safrole::SafroleState, services::ServiceAccounts, timeslot::Timeslot};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use thiserror::Error;

lazy_static! {
    pub static ref STATE_CACHE: StateCache = StateCache::new();
}

#[derive(Debug, Error)]
pub enum StateCacheError {
    #[error("Failed to acquire read lock: {0}")]
    ReadLockError(String),
    #[error("Failed to acquire write lock: {0}")]
    WriteLockError(String),
    #[error("Safrole state not found for hash key: {0:?}")]
    SafroleStateNotFound(Hash32),
    #[error("StateCache error: {0}")]
    Other(String),
}

pub struct StateCache {
    safrole_state: Arc<RwLock<HashMap<Hash32, SafroleState>>>,
    service_accounts: Arc<RwLock<HashMap<Hash32, ServiceAccounts>>>,
    timeslot: Arc<RwLock<HashMap<Hash32, Timeslot>>>,
    // TODO: add other state components
}

impl Default for StateCache {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: better implementation of the `ServiceAccounts` state cache, accessed via account address
// TODO: commit mechanism for finalized state write-set & rollback mechanism for invalid write-set
impl StateCache {
    // State component identifiers
    const SAFROLE: &'static str = "safrole";
    const SERVICE_ACCOUNTS: &'static str = "service_accounts";
    const TIMESLOT: &'static str = "timeslot";

    pub fn new() -> Self {
        Self {
            safrole_state: Arc::new(RwLock::new(HashMap::new())),
            service_accounts: Arc::new(RwLock::new(HashMap::new())),
            timeslot: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // TODO: impl
    fn get_current_hash(&self) -> Hash32 {
        todo!()
    }

    // Safrole methods
    pub fn add_safrole_state_cache(&self, state: SafroleState) -> Result<(), StateCacheError> {
        let hash = self.get_current_hash();

        let mut safrole_state = self
            .safrole_state
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        safrole_state.insert(hash, state);
        Ok(())
    }

    pub fn get_safrole_state_cache(&self) -> Result<Option<SafroleState>, StateCacheError> {
        let hash = self.get_current_hash();

        let safrole_state = self
            .safrole_state
            .read()
            .map_err(|e| StateCacheError::ReadLockError(e.to_string()))?;
        Ok(safrole_state.get(&hash).cloned())
    }

    pub fn remove_safrole_state_cache(&self) -> Result<Option<SafroleState>, StateCacheError> {
        let hash = self.get_current_hash();

        let mut safrole_state = self
            .safrole_state
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        Ok(safrole_state.remove(&hash))
    }

    // ServiceAccounts methods
    pub fn add_service_accounts_cache(
        &self,
        accounts: ServiceAccounts,
    ) -> Result<(), StateCacheError> {
        let hash = self.get_current_hash();

        let mut service_accounts = self
            .service_accounts
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        service_accounts.insert(hash, accounts);
        Ok(())
    }

    pub fn get_service_accounts_cache(&self) -> Result<Option<ServiceAccounts>, StateCacheError> {
        let hash = self.get_current_hash();

        let service_accounts = self
            .service_accounts
            .read()
            .map_err(|e| StateCacheError::ReadLockError(e.to_string()))?;
        Ok(service_accounts.get(&hash).cloned())
    }

    pub fn remove_service_accounts_cache(
        &self,
    ) -> Result<Option<ServiceAccounts>, StateCacheError> {
        let hash = self.get_current_hash();

        let mut service_accounts = self
            .service_accounts
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        Ok(service_accounts.remove(&hash))
    }

    // Timeslot methods
    pub fn add_timeslot_cache(&self, timeslot: Timeslot) -> Result<(), StateCacheError> {
        let hash = self.get_current_hash();
        let mut timeslot_cache = self
            .timeslot
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        timeslot_cache.insert(hash, timeslot);
        Ok(())
    }

    pub fn get_timeslot_cache(&self) -> Result<Option<Timeslot>, StateCacheError> {
        let hash = self.get_current_hash();
        let timeslot_cache = self
            .timeslot
            .read()
            .map_err(|e| StateCacheError::ReadLockError(e.to_string()))?;
        Ok(timeslot_cache.get(&hash).cloned())
    }

    pub fn remove_timeslot_cache(&self) -> Result<Option<Timeslot>, StateCacheError> {
        let hash = self.get_current_hash();
        let mut timeslot_cache = self
            .timeslot
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        Ok(timeslot_cache.remove(&hash))
    }
}
