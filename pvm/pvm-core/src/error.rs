use crate::{
    program::instruction::opcode::Opcode,
    state::{memory::MemoryError, vm_state::RegIndex},
};
use fr_codec::JamCodecError;
use fr_common::UnsignedGas;
use fr_pvm_types::common::{MemAddress, RegValue};
use thiserror::Error;

/// PVM Core Error Codes
#[derive(Debug, Error)]
pub enum VMCoreError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Too large gas charge value: {0}")]
    TooLargeGasCharge(UnsignedGas),
    #[error("Gas counter value overflowed")]
    GasCounterOverflow,
    #[error("Invalid program")]
    InvalidProgram,
    #[error("Program arguments size limit exceeded")]
    ProgramArgsSizeLimitExceeded,
    #[error("Invalid instruction format")]
    InvalidInstructionFormat,
    #[error("Dynamic jump target {0} is out of bounds in the jump table")]
    JumpTableOutOfBounds(usize),
    #[error("Invalid register value (index={0}, val={1})")]
    InvalidRegVal(RegIndex, RegValue),
    #[error("Invalid register index: {0}")]
    InvalidRegIndex(RegIndex),
    #[error("Invalid PC value (val={0})")]
    InvalidPCVal(RegValue),
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
    #[error("Forbidden memory access (address below 2^16): {0}")]
    ForbiddenMemZone(MemAddress),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("MemoryError: {0}")]
    MemoryError(#[from] MemoryError),
}
