use crate::types::extrinsics::Extrinsics;
use fr_common::Hash32;
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
pub enum XtDBError {
    #[error("CachedDBError: {0}")]
    CachedDBError(#[from] CachedDBError),
}

/// Extrinsics storage.
///
/// `db` is a cached key-value database to store block extrinsics.
/// Entries of the `db` are keyed by extrinsics hash.
pub struct XtDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<Hash32, Extrinsics>,
}

impl XtDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, XtDBError> {
        Ok(self.db.cf_handle()?)
    }

    /// Get an extrinsics entry by its hash from the cache or the DB.
    pub async fn get_xt(&self, xt_hash: &Hash32) -> Result<Option<Extrinsics>, XtDBError> {
        Ok(self.db.get_entry(xt_hash).await?)
    }

    /// Set an extrinsics entry.
    pub async fn set_xt(&self, xt_hash: &Hash32, xts: Extrinsics) -> Result<(), XtDBError> {
        self.db.put_entry(xt_hash, xts).await?;
        Ok(())
    }
}
