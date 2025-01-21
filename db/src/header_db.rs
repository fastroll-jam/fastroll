use crate::{KeyValueDBError, RocksDBConfig, KVDB};
use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamDecode, JamEncode};
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_types::block::header::{BlockHeader, BlockHeaderError};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockHeaderDBError {
    #[error("Header DB is not initialized")]
    HeaderDBNotInitialized,
    #[error("Header at index {0} not found")]
    HeaderNotFound(String),
    #[error("Staging header not initialized")]
    StagingHeaderNotInitialized,
    #[error("Staging header is already initialized")]
    StagingHeaderAlreadyInitialized,
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("KeyValueDBError: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// Main storage and cache for block headers.
///
/// Block headers are stored in the database indexed by both the timeslot and the header hash.
pub struct BlockHeaderDB {
    /// KeyValueDB type.
    db: Option<Arc<KVDB>>,
    /// Cache for storing block headers, keyed by timeslot index.
    cache: Arc<DashMap<u32, BlockHeader>>,
    /// Mutable staging header used for block construction.
    staging_header: Option<BlockHeader>,
}

impl BlockHeaderDB {
    pub fn initialize_for_test() -> Self {
        Self {
            db: None,
            cache: Arc::new(DashMap::new()),
            staging_header: Some(BlockHeader::new(HASH32_EMPTY)),
        }
    }

    pub fn open(config: &RocksDBConfig, cache_size: usize) -> Result<Self, BlockHeaderDBError> {
        let db = KVDB::open(config)?;
        Ok(Self {
            db: Some(Arc::new(db)),
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

        let db = self
            .db
            .as_ref()
            .ok_or(BlockHeaderDBError::HeaderDBNotInitialized)?;

        let timeslot_key = format!("T::{}", timeslot_index).into_bytes();

        let header_encoded =
            db.get_entry(&timeslot_key)?
                .ok_or(BlockHeaderDBError::HeaderNotFound(
                    timeslot_index.to_string(),
                ))?;

        let header = BlockHeader::decode(&mut header_encoded.as_slice())?;
        self.cache.insert(timeslot_index, header.clone());

        Ok(header)
    }

    /// Get a block header by its hash from the DB.
    pub fn get_header_by_hash(
        &self,
        header_hash: &Hash32,
    ) -> Result<BlockHeader, BlockHeaderDBError> {
        let db = self
            .db
            .as_ref()
            .ok_or(BlockHeaderDBError::HeaderDBNotInitialized)?;

        let header_hash_string = format!("H::{}", header_hash.encode_hex());
        let header_hash_key = header_hash_string.clone().into_bytes();

        let header_encoded = db
            .get_entry(&header_hash_key)?
            .ok_or(BlockHeaderDBError::HeaderNotFound(header_hash_string))?;

        Ok(BlockHeader::decode(&mut header_encoded.as_slice())?)
    }

    fn commit_header(&self, header: &BlockHeader) -> Result<(), BlockHeaderDBError> {
        let db = self
            .db
            .as_ref()
            .ok_or(BlockHeaderDBError::HeaderDBNotInitialized)?;

        let timeslot_key = format!("T::{}", header.timeslot_index).into_bytes();
        let header_hash_key = format!("H::{}", header.hash()?.encode_hex()).into_bytes();

        let header_encoded = header.encode()?;

        db.put_entry(&timeslot_key, &header_encoded)?;
        db.put_entry(&header_hash_key, &header_encoded)?;
        self.cache.insert(header.timeslot_index, header.clone());

        Ok(())
    }

    pub fn init_staging_header(&mut self, parent_hash: Hash32) -> Result<(), BlockHeaderDBError> {
        if let Some(_staging_header) = self.get_staging_header() {
            return Err(BlockHeaderDBError::StagingHeaderAlreadyInitialized);
        }

        self.staging_header = Some(BlockHeader::new(parent_hash));

        Ok(())
    }

    pub fn get_staging_header(&self) -> Option<&BlockHeader> {
        self.staging_header.as_ref()
    }

    pub fn assert_staging_header_initialized(&self) -> Result<(), BlockHeaderDBError> {
        if self.staging_header.is_some() {
            Ok(())
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
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
