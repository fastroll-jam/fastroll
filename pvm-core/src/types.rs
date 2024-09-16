use crate::{
    constants::DATA_SEGMENTS_SIZE,
    hostcall::HostCallType,
    memory::{MemAddress, MemoryError},
};
use jam_codec::JamCodecError;
use jam_crypto::utils::CryptoError;
use jam_state::global_state::GlobalStateError;
use thiserror::Error;

/// PVM Error Codes
#[derive(Debug, Error)]
pub enum VMError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Invalid program counter value")]
    InvalidProgramCounter,
    #[error("Panic")]
    Panic,
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
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("HostCallError: {0}")]
    HostCallError(#[from] Box<HostCallError>),
}

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
    #[error("GlobalStateError: {0}")]
    GlobalStateError(#[from] GlobalStateError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("VMError: {0}")]
    VMError(#[from] Box<VMError>),
}

// TODO: better error codes to bypass the circular dependency
impl From<HostCallError> for VMError {
    fn from(err: HostCallError) -> Self {
        VMError::HostCallError(Box::new(err))
    }
}

impl From<VMError> for HostCallError {
    fn from(err: VMError) -> Self {
        HostCallError::VMError(Box::new(err))
    }
}

/// PVM Invocation Exit Reasons
pub enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault(MemAddress),
    HostCall(HostCallType),
}

pub type ExportDataSegment = [u8; DATA_SEGMENTS_SIZE];
