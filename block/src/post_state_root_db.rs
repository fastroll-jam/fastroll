use fr_common::{BlockHeaderHash, StateRoot};
use fr_db::{
    core::{
        cached_db::{CachedDB, CachedDBError},
        core_db::CoreDB,
    },
    ColumnFamily,
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PostStateRootDbError {
    #[error("CachedDBError: {0}")]
    CachedDBError(#[from] CachedDBError),
}

/// A storage that holds mapping of block header hashes and their post state roots.
///
/// Used for prior state root validation in block headers.
pub struct PostStateRootDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<BlockHeaderHash, StateRoot>,
}

impl PostStateRootDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, PostStateRootDbError> {
        Ok(self.db.cf_handle()?)
    }

    pub async fn get_post_state_root(
        &self,
        header_hash: &BlockHeaderHash,
    ) -> Result<Option<StateRoot>, PostStateRootDbError> {
        Ok(self.db.get_entry(header_hash).await?)
    }

    pub async fn set_post_state_root(
        &self,
        header_hash: &BlockHeaderHash,
        post_state_root: StateRoot,
    ) -> Result<(), PostStateRootDbError> {
        Ok(self.db.put_entry(header_hash, post_state_root).await?)
    }
}
