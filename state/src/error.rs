use crate::{state_db::StateDBError, types::PendingReportsError};
use fr_codec::JamCodecError;
use fr_crypto::error::CryptoError;
use fr_db::core::cached_db::CachedDBError;
use fr_merkle::common::MerkleError;
use fr_state_merkle::error::StateMerkleError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("State key not initialized")]
    StateKeyNotInitialized,
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
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateMerkle error: {0}")]
    StateMerkleError(#[from] StateMerkleError),
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
