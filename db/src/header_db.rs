use crate::{KeyValueDB, KeyValueDBError, RocksDBConfig};
use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamDecode, JamEncode};
use rjam_common::Hash32;
use rjam_types::block::header::BlockHeader;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockHeaderDBError {
    #[error("Header at timeslot {0} not found")]
    HeaderNotFound(u32),
    #[error("Staging header not initialized")]
    StagingHeaderNotInitialized,
    #[error("Staging header is already initialized")]
    StagingHeaderAlreadyInitialized,
    #[error("KeyValueDBError: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

pub struct BlockHeaderDB {
    /// KeyValueDB type.
    db: KeyValueDB,
    /// Cache for storing block headers, keyed by timeslot index.
    cache: Arc<DashMap<u32, BlockHeader>>,
    /// Mutable staging header used for block construction.
    staging_header: Option<BlockHeader>,
}

impl BlockHeaderDB {
    pub fn open(config: &RocksDBConfig, cache_size: usize) -> Result<Self, BlockHeaderDBError> {
        let db = KeyValueDB::new(config)?;
        Ok(Self {
            db,
            cache: Arc::new(DashMap::with_capacity(cache_size)),
            staging_header: None,
        })
    }

    /// Get a block header by timeslot, either from the DB or the cache.
    pub fn get_header(&self, timeslot_index: u32) -> Result<BlockHeader, BlockHeaderDBError> {
        // lookup the cache
        if let Some(header) = self.cache.get(&timeslot_index) {
            return Ok(header.clone());
        }

        let key = timeslot_index.to_le_bytes();

        let header_encoded = self
            .db
            .get_entry(&key)?
            .ok_or(BlockHeaderDBError::HeaderNotFound(timeslot_index))?;

        let header = BlockHeader::decode(&mut header_encoded.as_slice())?;
        self.cache.insert(timeslot_index, header.clone());

        Ok(header)
    }

    fn commit_header(&self, header: &BlockHeader) -> Result<(), BlockHeaderDBError> {
        let key = header.timeslot_index.to_le_bytes();
        let header_encoded = header.encode()?;

        self.db.put_entry(&key, &header_encoded)?;
        self.cache.insert(header.timeslot_index, header.clone());

        Ok(())
    }

    pub fn initialize_staging_header(
        &mut self,
        parent_hash: Hash32,
        timeslot_index: u32,
    ) -> Result<(), BlockHeaderDBError> {
        if let Some(_staging_header) = self.get_staging_header() {
            return Err(BlockHeaderDBError::StagingHeaderAlreadyInitialized);
        }

        self.staging_header = Some(BlockHeader::new(parent_hash, timeslot_index));

        Ok(())
    }

    pub fn get_staging_header(&self) -> Option<&BlockHeader> {
        self.staging_header.as_ref()
    }

    pub fn drop_staging_header(&mut self) {
        self.staging_header = None;
    }

    pub fn update_staging_header<F>(&mut self, f: F) -> Result<(), BlockHeaderDBError>
    where
        F: FnOnce(&mut BlockHeader),
    {
        if let Some(ref mut header) = self.staging_header {
            f(header);
            Ok(())
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }

    pub fn commit_staging_header(&mut self) -> Result<(), BlockHeaderDBError> {
        if let Some(header) = self.staging_header.take() {
            self.commit_header(&header)
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }
}
