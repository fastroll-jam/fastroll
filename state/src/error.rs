use crate::{state_db::StateDBError, types::PendingReportsError};
use fr_codec::JamCodecError;
use fr_crypto::error::CryptoError;
use fr_db::core::cached_db::{CacheItemCodecError, CachedDBError};
use fr_merkle::common::MerkleError;
use fr_state_merkle_v2::types::StateMerkleError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("State key not initialized ({0})")]
    StateKeyNotInitialized(String),
    #[error("Cache entry not found")]
    CacheEntryNotFound,
    #[error("Cache entry is clean")]
    NotDirtyCache,
    #[error("Unexpected entry type")]
    UnexpectedEntryType,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Wrong StateMut operation type")]
    WrongStateMutType,
    #[error("State Entry with the state key already exists")]
    StateEntryAlreadyExists,
    #[error("MerkleActor is closed")]
    MerkleActorClosed,
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateMerkle error: {0}")]
    StateMerkleError(#[from] StateMerkleError),
    #[error("CacheItemCodec error: {0}")]
    CacheItemCodecError(#[from] CacheItemCodecError),
    #[error("MerkleError error: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("StateDB error: {0}")]
    StateDBError(#[from] StateDBError),
    #[error("CachedDB error: {0}")]
    CachedDBError(#[from] CachedDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("PendingReports Error")]
    PendingReportsError(#[from] PendingReportsError),
}
