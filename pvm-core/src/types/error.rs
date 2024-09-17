use crate::state::memory::MemoryError;
use jam_codec::JamCodecError;
use jam_crypto::utils::CryptoError;
use jam_state::{cache::StateCacheError, global_state::GlobalStateError};
use thiserror::Error;

// PVM Error Codes
#[derive(Debug, Error)]
pub enum PVMError {
    #[error("VMCoreError: {0}")]
    VMCoreError(#[from] VMCoreError),
    #[error("HostCallError: {0}")]
    HostCallError(#[from] HostCallError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("GlobalStateError: {0}")]
    GlobalStateError(#[from] GlobalStateError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateCacheError: {0}")]
    StateCacheError(#[from] StateCacheError),
}

/// PVM Core Error Codes
#[derive(Debug, Error)]
pub enum VMCoreError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Invalid program")]
    InvalidProgram,
    #[error("Invalid instruction format")]
    InvalidInstructionFormat,
    #[error("Invalid opcode")]
    InvalidOpcode,
    #[error("Invalid immediate value")]
    InvalidImmediateValue,
    #[error("Invalid host call type")]
    InvalidHostCallType,
}

/// PVM Host Call Error Codes
#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Invalid register indices")]
    InvalidRegisters,
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Exit reason of the inner PVM invocation is invalid")]
    InvalidExitReason,
}
