use fr_codec::JamCodecError;
use fr_crypto::error::CryptoError;
use fr_limited_vec::LimitedVecError;
use fr_pvm_core::{error::VMCoreError, state::memory::MemoryError};
use fr_state::error::StateManagerError;
use thiserror::Error;

/// PVM Host Call Error Codes
#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Data segment is too large")]
    DataSegmentTooLarge,
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Accumulator account is not initialized in the service accounts partial state")]
    AccumulatorAccountNotInitialized,
    #[error("Service id overflowed")]
    ServiceIdOverflow,
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Failed to insert an entry from an account storage")]
    AccountStorageInsertionFailed,
    #[error("Failed to remove an entry from an account storage")]
    AccountStorageRemovalFailed,
    #[error("Exit reason of the PVM invocation is invalid")]
    InvalidExitReason,
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("VMCoreError: {0}")]
    VMCoreError(#[from] VMCoreError),
    #[error("PartialStateError: {0}")]
    PartialStateError(#[from] PartialStateError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

/// PVM Host Call Partial State Error Codes
#[derive(Debug, Error)]
pub enum PartialStateError {
    #[error("Account not found from the global state")]
    AccountNotFoundFromGlobalState,
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
