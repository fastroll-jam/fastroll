use crate::types::{
    block::{BlockHeader, BlockHeaderError},
    extrinsics::ExtrinsicsError,
};
use fr_codec::prelude::*;
use fr_common::BlockHeaderHash;

use crate::ancestors::{AncestorEntry, AncestorSet};
use fr_crypto::error::CryptoError;
use fr_db::{
    core::{
        cached_db::{CacheItem, CacheItemCodecError, CachedDB, CachedDBError},
        core_db::CoreDB,
    },
    ColumnFamily, WriteBatch,
};
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockHeaderDBError {
    #[error("Header at index {0} not found")]
    HeaderNotFound(String),
    #[error("Staging header not initialized")]
    StagingHeaderNotInitialized,
    #[error("Staging header is already initialized")]
    StagingHeaderAlreadyInitialized,
    #[error("Invalid timestamp: prior to the JAM common era")]
    InvalidTimestamp,
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
    #[error("CachedDBError: {0}")]
    CachedDBError(#[from] CachedDBError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CacheItemCodecError: {0}")]
    CacheItemCodecError(#[from] CacheItemCodecError),
}

impl CacheItem for BlockHeader {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        Ok(self.encode()?)
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Result<Self, CacheItemCodecError>
    where
        Self: Sized,
    {
        Ok(Self::decode(&mut val.as_slice())?)
    }
}

// TODO: If `BlockHeaderDB` should be pruned, ensure to retain at least `L` timeslots' worth of ancestor headers set. (GuaranteesXt lookup anchor block validation requirement)
/// The main storage to store block headers.
///
/// `db` is a cached key-value database to store block headers.
/// Entries of the `db` are keyed by block header hash.
pub struct BlockHeaderDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<BlockHeaderHash, BlockHeader>,
    /// A known best block header determined by GRANDPA.
    best_header: Mutex<BlockHeader>,
    /// An in-memory cache of block header ancestor set.
    ancestors: Mutex<AncestorSet>,
}

impl BlockHeaderDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
            best_header: Mutex::new(BlockHeader::default()),
            ancestors: Mutex::new(AncestorSet::new()),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, BlockHeaderDBError> {
        Ok(self.db.cf_handle()?)
    }

    /// Get a block header by its hash from the cache or the DB.
    pub async fn get_header(
        &self,
        header_hash: &BlockHeaderHash,
    ) -> Result<Option<BlockHeader>, BlockHeaderDBError> {
        Ok(self.db.get_entry(header_hash).await?)
    }

    pub async fn commit_header(
        &self,
        header: BlockHeader,
    ) -> Result<BlockHeaderHash, BlockHeaderDBError> {
        let hash = header.hash()?;
        self.db.put_entry(&hash, header).await?;
        Ok(hash)
    }

    fn best_header_guard(&self) -> MutexGuard<'_, BlockHeader> {
        self.best_header.lock().unwrap_or_else(|poisoned| {
            tracing::error!("Best header mutex poisoned; continuing with inner data");
            poisoned.into_inner()
        })
    }

    pub fn get_best_header(&self) -> BlockHeader {
        self.best_header_guard().clone()
    }

    pub fn set_best_header(&self, new_best_header: BlockHeader) {
        let mut best_header_guard = self.best_header_guard();
        *best_header_guard = new_best_header;
    }

    fn ancestors_guard(&self) -> MutexGuard<'_, AncestorSet> {
        self.ancestors.lock().unwrap_or_else(|poisoned| {
            tracing::error!("Ancestors guard poisoned; continuing with inner data");
            poisoned.into_inner()
        })
    }

    pub fn header_exists_in_ancestor_set(&self, entry: &AncestorEntry) -> bool {
        self.ancestors_guard().contains(entry)
    }

    pub async fn insert_header(
        &self,
        header_hash: BlockHeaderHash,
        header: BlockHeader,
    ) -> Result<(), BlockHeaderDBError> {
        // Insert to AncestorSet
        let ancestor_entry = (header.timeslot_index(), header_hash.clone());
        self.ancestors_guard().add(ancestor_entry);

        // Insert to DB
        self.db.put_entry(&header_hash, header).await?;
        Ok(())
    }

    pub async fn batch_insert_headers(
        &self,
        headers: Vec<(BlockHeaderHash, BlockHeader)>,
    ) -> Result<(), BlockHeaderDBError> {
        // Insert to AncestorSet
        let ancestor_entries: Vec<AncestorEntry> = headers
            .iter()
            .map(|(hash, header)| (header.timeslot_index(), hash.clone()))
            .collect();
        self.ancestors_guard().add_multiple(ancestor_entries);

        // Insert to DB
        let mut batch = WriteBatch::default();
        let mut header_writes = Vec::with_capacity(headers.len());
        for (header_hash, header) in headers {
            header_writes.push((header_hash.clone(), Some(header.clone())));
            batch.put_cf(
                self.cf_handle()?,
                header_hash.as_slice(),
                header.into_db_value()?,
            );
        }
        self.db
            .commit_write_batch_and_sync_cache(batch, &header_writes)
            .await?;
        Ok(())
    }

    pub fn batch_insert_to_ancestor_set(
        &self,
        entries: Vec<AncestorEntry>,
    ) -> Result<(), BlockHeaderDBError> {
        // Insert to AncestorSet
        self.ancestors_guard().add_multiple(entries);
        Ok(())
    }
}
