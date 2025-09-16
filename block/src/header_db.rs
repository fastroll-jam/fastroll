use crate::types::{
    block::{BlockHeader, BlockHeaderError},
    extrinsics::ExtrinsicsError,
};
use fr_codec::prelude::*;
use fr_common::BlockHeaderHash;

use crate::ancestors::AncestorSet;
use fr_crypto::error::CryptoError;
use fr_db::{
    core::{
        cached_db::{CacheItem, CachedDB, CachedDBError},
        core_db::CoreDB,
    },
    ColumnFamily, WriteBatch,
};
use std::sync::{Arc, Mutex};
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
}

impl CacheItem for BlockHeader {
    fn into_db_value(self) -> Vec<u8> {
        self.encode().expect("Failed to encode BlockHeader")
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self::decode(&mut val.as_slice()).expect("Failed to decode BlockHeader")
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
    pub ancestors: AncestorSet,
}

impl BlockHeaderDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
            best_header: Mutex::new(BlockHeader::default()),
            ancestors: AncestorSet::new(),
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

    pub fn get_best_header(&self) -> BlockHeader {
        self.best_header.lock().unwrap().clone()
    }

    pub fn set_best_header(&self, new_best_header: BlockHeader) {
        let mut best_header = self.best_header.lock().unwrap();
        *best_header = new_best_header;
    }

    pub fn header_exists_in_ancestor_set(&self, header_hash: &BlockHeaderHash) -> bool {
        self.ancestors.contains(header_hash)
    }

    pub async fn insert_header(
        &self,
        header_hash: BlockHeaderHash,
        header: BlockHeader,
    ) -> Result<(), BlockHeaderDBError> {
        self.db.put_entry(&header_hash, header).await?;
        Ok(())
    }

    pub async fn batch_insert_headers(
        &self,
        headers: Vec<(BlockHeaderHash, BlockHeader)>,
    ) -> Result<(), BlockHeaderDBError> {
        let mut batch = WriteBatch::default();
        for (header_hash, header) in headers {
            batch.put_cf(
                self.cf_handle()?,
                header_hash.as_slice(),
                header.into_db_value(),
            );
        }
        self.db.commit_write_batch(batch).await?;
        Ok(())
    }
}
