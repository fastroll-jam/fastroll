use crate::{
    program::opcode::Opcode,
    state::memory::{MemAddress, MemoryError},
};
use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use rjam_state::error::StateManagerError;
use thiserror::Error;

// PVM Error Codes
#[derive(Debug, Error)]
pub enum PVMError {
    #[error("Account code not found")]
    AccountCodeNotFound,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Page Fault at Address {0}")]
    PageFault(MemAddress),
    #[error("Invalid memory zone")]
    InvalidMemZone,
    #[error("Spawned accumulate task panicked")]
    AccumulateTaskPanicked,
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
    #[error("PartialStateError: {0}")]
    PartialStateError(#[from] PartialStateError),
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
    #[error("Program arguments size limit exceeded")]
    ProgramArgsSizeLimitExceeded,
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
    #[error("Immediate value not found in the instruction. Opcode: {0:?}")]
    ImmValNotFound(Opcode),
    #[error("Source register index not found in the instruction. Opcode: {0:?}")]
    SourceRegIdxNotFound(Opcode),
    #[error("Destination register index not found in the instruction. Opcode: {0:?}")]
    DestinationRegIdxNotFound(Opcode),
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
    #[error("Account not found from the global account state")]
    AccountNotFound,
    #[error("Exit reason of the PVM invocation is invalid")]
    InvalidExitReason,
    #[error("State manager holding polluted data")]
    StateManagerPollution,
}

/// PVM Host Call Partial State Error Codes
#[derive(Debug, Error)]
pub enum PartialStateError {
    #[error("Account not found from the global state")]
    AccountNotFoundFromGlobalState,
    #[error("Attempted to delete account storage/preimage entry that doesn't exist")]
    MissingAccountEntryDeletion,
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
