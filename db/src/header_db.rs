use crate::core::{CoreDB, CoreDBError, HEADER_CF_NAME};
use dashmap::DashMap;
use rjam_block::types::{
    block::{BlockHeader, BlockHeaderError, EpochMarker, WinningTicketsMarker},
    extrinsics::{disputes::OffendersHeaderMarker, Extrinsics, ExtrinsicsError},
};
use rjam_clock::Clock;
use rjam_codec::{JamCodecError, JamDecode, JamEncode};
use rjam_common::{BandersnatchSignature, Hash32, ValidatorIndex};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use rocksdb::BoundColumnFamily;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
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
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// Main storage and cache for block headers.
///
/// Block headers are stored in the database indexed by both the timeslot and the header hash.
pub struct BlockHeaderDB {
    /// KeyValueDB type.
    core: Arc<CoreDB>,
    /// Cache for storing block headers, keyed by timeslot index.
    cache: DashMap<u32, BlockHeader>,
    /// Mutable staging header used for block construction.
    staging_header: Mutex<Option<BlockHeader>>,
}

impl BlockHeaderDB {
    pub fn new(core: Arc<CoreDB>, cache_size: usize) -> Self {
        Self {
            core,
            cache: DashMap::with_capacity(cache_size),
            staging_header: Mutex::new(None),
        }
    }

    pub fn open<P: AsRef<Path>>(
        path: P,
        create_if_missing: bool,
        cache_size: usize,
    ) -> Result<Self, BlockHeaderDBError> {
        Ok(Self::new(
            Arc::new(CoreDB::open(path, create_if_missing)?),
            cache_size,
        ))
    }

    pub fn cf_handle(&self) -> Result<Arc<BoundColumnFamily>, BlockHeaderDBError> {
        self.core.cf_handle(HEADER_CF_NAME).map_err(|e| e.into())
    }

    /// Get a block header by timeslot, either from the DB or the cache.
    pub async fn get_header(&self, timeslot_index: u32) -> Result<BlockHeader, BlockHeaderDBError> {
        // lookup the cache
        if let Some(header) = self.cache.get(&timeslot_index) {
            return Ok(header.clone());
        }

        let timeslot_key = format!("T::{}", timeslot_index).into_bytes();

        let header_encoded = self.core.get_header(&timeslot_key).await?.ok_or(
            BlockHeaderDBError::HeaderNotFound(timeslot_index.to_string()),
        )?;

        let header = BlockHeader::decode(&mut header_encoded.as_slice())?;
        self.cache.insert(timeslot_index, header.clone());

        Ok(header)
    }

    /// Get a block header by its hash from the DB.
    pub async fn get_header_by_hash(
        &self,
        header_hash: &Hash32,
    ) -> Result<BlockHeader, BlockHeaderDBError> {
        let header_hash_string = format!("H::{}", header_hash.encode_hex());
        let header_hash_key = header_hash_string.clone().into_bytes();

        let header_encoded = self
            .core
            .get_header(&header_hash_key)
            .await?
            .ok_or(BlockHeaderDBError::HeaderNotFound(header_hash_string))?;

        Ok(BlockHeader::decode(&mut header_encoded.as_slice())?)
    }

    async fn commit_header(&self, header: &BlockHeader) -> Result<(), BlockHeaderDBError> {
        let timeslot_key = format!("T::{}", header.timeslot_index).into_bytes();
        let header_hash_key = format!("H::{}", header.hash()?.encode_hex()).into_bytes();

        let header_encoded = header.encode()?;

        self.core.put_header(&timeslot_key, &header_encoded).await?;
        self.core
            .put_header(&header_hash_key, &header_encoded)
            .await?;
        self.cache.insert(header.timeslot_index, header.clone());

        Ok(())
    }

    pub fn init_staging_header(&mut self, parent_hash: Hash32) -> Result<(), BlockHeaderDBError> {
        if self.get_staging_header().is_some() {
            return Err(BlockHeaderDBError::StagingHeaderAlreadyInitialized);
        }

        let mut guard = self.staging_header.lock().unwrap();
        *guard = Some(BlockHeader::new(parent_hash));

        Ok(())
    }

    pub fn get_staging_header(&self) -> Option<BlockHeader> {
        self.staging_header.lock().unwrap().clone()
    }

    pub fn assert_staging_header_initialized(&self) -> Result<(), BlockHeaderDBError> {
        if self.staging_header.lock().unwrap().is_some() {
            Ok(())
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }

    pub fn drop_staging_header(&mut self) {
        self.staging_header.lock().unwrap().take();
    }

    fn update_staging_header<F>(&mut self, f: F) -> Result<(), BlockHeaderDBError>
    where
        F: FnOnce(&mut BlockHeader),
    {
        let mut guard = self.staging_header.lock().unwrap();
        if let Some(header) = guard.as_mut() {
            f(header);
            Ok(())
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }

    pub async fn commit_staging_header(&mut self) -> Result<(), BlockHeaderDBError> {
        let maybe_header = self.staging_header.lock().unwrap().take();
        if let Some(header) = maybe_header {
            self.commit_header(&header).await
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }

    // Staging header setters
    pub fn set_timeslot(&mut self) -> Result<u32, BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;

        if let Some(curr_timeslot_index) = Clock::now_jam_timeslot() {
            self.update_staging_header(|h| {
                h.timeslot_index = curr_timeslot_index;
            })?;
            Ok(curr_timeslot_index)
        } else {
            Err(BlockHeaderDBError::InvalidTimestamp)
        }
    }

    fn header_extrinsic_hash(xt: &Extrinsics) -> Result<Hash32, BlockHeaderDBError> {
        let mut buf = vec![];
        hash::<Blake2b256>(&xt.tickets.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&xt.preimage_lookups.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&xt.guarantees.encode_with_hashed_reports()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&xt.assurances.encode()?)?.encode_to(&mut buf)?;
        hash::<Blake2b256>(&xt.disputes.encode()?)?.encode_to(&mut buf)?;
        Ok(hash::<Blake2b256>(&buf)?)
    }

    pub fn set_extrinsic_hash(&mut self, xt: &Extrinsics) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        let xt_hash = Self::header_extrinsic_hash(xt)?;
        self.update_staging_header(|h| {
            h.extrinsic_hash = xt_hash;
        })
    }

    pub fn set_vrf_signature(
        &mut self,
        vrf_sig: &BandersnatchSignature,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.vrf_signature = *vrf_sig;
        })
    }

    pub fn set_block_seal(
        &mut self,
        block_seal: &BandersnatchSignature,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.block_seal = *block_seal;
        })
    }

    pub fn set_block_author_index(
        &mut self,
        block_author_index: ValidatorIndex,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.block_author_index = block_author_index;
        })
    }

    pub fn set_epoch_marker(
        &mut self,
        epoch_marker: &EpochMarker,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.epoch_marker = Some(epoch_marker.clone());
        })
    }

    pub fn set_winning_tickets_marker(
        &mut self,
        winning_tickets_marker: &WinningTicketsMarker,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.winning_tickets_marker = Some(*winning_tickets_marker);
        })
    }

    pub fn set_offenders_marker(
        &mut self,
        offenders_marker: &OffendersHeaderMarker,
    ) -> Result<(), BlockHeaderDBError> {
        self.assert_staging_header_initialized()?;
        self.update_staging_header(|h| {
            h.offenders_marker = offenders_marker.items.to_vec();
        })
    }
}
