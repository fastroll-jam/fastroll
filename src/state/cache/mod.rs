use crate::{common::Hash32, state::components::safrole::SafroleState};
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
    // TODO: add other state components
}

impl Default for StateCache {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: commit mechanism for finalized state write-set & rollback mechanism for invalid write-set
impl StateCache {
    // State component identifiers
    const SAFROLE: &'static str = "safrole";
    pub fn new() -> Self {
        Self {
            safrole_state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_safrole_state(
        &self,
        hash: Hash32,
        state: SafroleState,
    ) -> Result<(), StateCacheError> {
        let mut safrole_state = self
            .safrole_state
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        safrole_state.insert(hash, state);
        Ok(())
    }

    pub fn get_safrole_state(
        &self,
        hash: &Hash32,
    ) -> Result<Option<SafroleState>, StateCacheError> {
        let safrole_state = self
            .safrole_state
            .read()
            .map_err(|e| StateCacheError::ReadLockError(e.to_string()))?;
        Ok(safrole_state.get(hash).cloned())
    }

    pub fn remove_safrole_state(
        &self,
        hash: &Hash32,
    ) -> Result<Option<SafroleState>, StateCacheError> {
        let mut safrole_state = self
            .safrole_state
            .write()
            .map_err(|e| StateCacheError::WriteLockError(e.to_string()))?;
        Ok(safrole_state.remove(hash))
    }
}
