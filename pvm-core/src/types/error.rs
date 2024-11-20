use crate::state::memory::MemoryError;
use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use rjam_state::StateManagerError;
use thiserror::Error;

// PVM Error Codes
#[derive(Debug, Error)]
pub enum PVMError {
    #[error("New account address not initialized")]
    NewAccountAddressNotInitialized,
    #[error("Account code not found")]
    AccountCodeNotFound,
    #[error("VMCoreError: {0}")]
    VMCoreError(#[from] VMCoreError),
    #[error("HostCallError: {0}")]
    HostCallError(#[from] HostCallError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
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
    #[error("Invalid register value")]
    InvalidRegValue,
    #[error("Invalid memory value")]
    InvalidMemoryValue,
    #[error("Invalid immediate value")]
    InvalidImmediateValue,
    #[error("Invalid host call type")]
    InvalidHostCallType,
}

/// PVM Host Call Error Codes
#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Export data segment length mismatch: expected length {expected} but it was {actual}")]
    DataSegmentLengthMismatch { expected: usize, actual: usize },
    #[error("Invalid host call invocation context")]
    InvalidContext,
    #[error("Invalid register indices")]
    InvalidRegisters,
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Exit reason of the inner PVM invocation is invalid")]
    InvalidExitReason,
}
