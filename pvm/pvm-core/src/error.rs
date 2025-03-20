use crate::{program::instruction::opcode::Opcode, state::memory::MemoryError};
use rjam_codec::JamCodecError;
use rjam_pvm_types::common::MemAddress;
use thiserror::Error;

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
    #[error("Page Fault at Address {0}")]
    PageFault(MemAddress),
    #[error("Invalid memory zone")]
    InvalidMemZone,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
}
