use fr_db::core::{
    cached_db::CachedDB,
    core_db::{CoreDB, CoreDBError},
};
use fr_state_merkle::types::nodes::StateHash;
use std::{ops::Deref, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
}

/// A cached key-value database to store serialized state values,
/// which are not small enough to be embedded within Merkle trie leaves.
///
/// Entries of the `db` are keyed by hash of state value.
pub struct StateDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<StateHash, Vec<u8>>,
}

impl Deref for StateDB {
    type Target = CachedDB<StateHash, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl StateDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
        }
    }
}
