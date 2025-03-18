use crate::core::{
    cached_db::{CacheItem, CachedDB, CachedDBError},
    core_db::CoreDB,
};
use rjam_block::types::{
    block::{BlockHeader, BlockHeaderError, EpochMarker, WinningTicketsMarker},
    extrinsics::{disputes::OffendersHeaderMarker, Extrinsics, ExtrinsicsError},
};
use rjam_clock::Clock;
use rjam_codec::{JamCodecError, JamDecode, JamEncode};
use rjam_common::{BandersnatchSignature, Hash32, ValidatorIndex};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use rocksdb::ColumnFamily;
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

/// The main storage to store block headers.
///
/// `db` is a cached key-value database to store block headers.
/// Entries of the `db` are keyed by block header hash.
pub struct BlockHeaderDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<Hash32, BlockHeader>,
    /// Mutable staging header used for block construction.
    staging_header: Mutex<Option<BlockHeader>>,
}

impl BlockHeaderDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
            staging_header: Mutex::new(None),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, BlockHeaderDBError> {
        self.db.cf_handle().map_err(|e| e.into())
    }

    /// Get a block header by its hash from the cache or the DB.
    pub async fn get_header(
        &self,
        header_hash: &Hash32,
    ) -> Result<Option<BlockHeader>, BlockHeaderDBError> {
        Ok(self.db.get_entry(header_hash).await?)
    }

    async fn commit_header(&self, header: BlockHeader) -> Result<Hash32, BlockHeaderDBError> {
        let hash = header.hash()?;
        self.db.put_entry(&hash, header).await?;
        Ok(hash)
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

    /// Commits the staging header into `HeaderDB` and returns the hash of the new header.
    pub async fn commit_staging_header(&mut self) -> Result<Hash32, BlockHeaderDBError> {
        let maybe_header = self.staging_header.lock().unwrap().take();
        if let Some(header) = maybe_header {
            self.commit_header(header).await
        } else {
            Err(BlockHeaderDBError::StagingHeaderNotInitialized)
        }
    }

    // --- Staging header field setters

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
