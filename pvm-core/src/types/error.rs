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
    #[error("Too large gas counter value")]
    TooLargeGasCounter,
    #[error("Invalid program")]
    InvalidProgram,
    #[error("Invalid instruction format")]
    InvalidInstructionFormat,
    #[error("Invalid opcode")]
    InvalidOpcode,
    #[error("Dynamic jump target {0} is out of bounds in the jump table")]
    JumpTableOutOfBounds(usize),
    #[error("Invalid register value")]
    InvalidRegVal,
    #[error("Invalid register index: {0}")]
    InvalidRegIndex(usize),
    #[error("Invalid memory value")]
    InvalidMemVal,
    #[error("Invalid immediate value")]
    InvalidImmVal,
    #[error("Invalid offset value")]
    InvalidOffset,
    #[error("Invalid pc value")]
    InvalidPC,
    #[error("Invalid host call type")]
    InvalidHostCallType,
    #[error("Data length mismatch in memory state changes")]
    MemoryStateChangeDataLengthMismatch,
}

/// PVM Host Call Error Codes
#[derive(Debug, Error)]
pub enum HostCallError {
    #[error("Export data segment length mismatch: expected length {expected} but it was {actual}")]
    DataSegmentLengthMismatch { expected: usize, actual: usize },
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
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Exit reason of the inner PVM invocation is invalid")]
    InvalidExitReason,
}
