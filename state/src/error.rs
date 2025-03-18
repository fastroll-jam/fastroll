use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use rjam_db::{core::cached_db::CachedDBError, state_db::StateDBError};
use rjam_state_merkle::error::StateMerkleError;
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
    #[error("Account storage dictionary entry not found")]
    StorageEntryNotFound,
    #[error("Account lookups dictionary entry not found")]
    LookupsEntryNotFound,
    #[error("Wrong StateMut operation type")]
    WrongStateMutType,
    #[error("State Entry with the state key already exists")]
    StateEntryAlreadyExists,
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Merkle error: {0}")]
    StateMerkleError(#[from] StateMerkleError),
    #[error("StateDB error: {0}")]
    StateDBError(#[from] StateDBError),
    #[error("CachedDB error: {0}")]
    CachedDBError(#[from] CachedDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}
