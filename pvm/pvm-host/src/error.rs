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
    #[error("Account not found in the service account partial state")]
    AccountNotFoundInPartialState,
    #[error("Accumulator account is not initialized in the service accounts partial state")]
    AccumulatorAccountNotInitialized,
    #[error("Invalid register indices")]
    InvalidRegisters,
    #[error("Invalid memory write request as a result of host function execution")]
    InvalidMemoryWrite,
    #[error("Service id overflowed")]
    ServiceIdOverflow,
    #[error("Service account balance overflowed")]
    BalanceOverflow,
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Exit reason of the PVM invocation is invalid")]
    InvalidExitReason,
    #[error("State manager holding polluted data")]
    StateManagerPollution,
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
    #[error("Attempted to delete account storage/preimage entry that doesn't exist")]
    MissingAccountEntryDeletion,
    #[error("LimitedVecError: {0}")]
    LimitedVecError(#[from] LimitedVecError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
