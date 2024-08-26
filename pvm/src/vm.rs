use crate::constants::REGISTERS_COUNT;
use jam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamInput};
use jam_common::{Octets, UnsignedGas};
use thiserror::Error;

/// Polka Virtual Machine

#[derive(Debug, Error)]
pub(crate) enum VMError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Invalid program counter value")]
    InvalidProgramCounter,
    #[error("Memory access violation: {0}")]
    MemoryAccessViolation(u8),
    #[error("Memory cell unavailable: {0}")]
    MemoryUnavailable(u8),
    #[error("Panic")]
    Panic,
    #[error("Invalid program")]
    InvalidProgram,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

struct PVM {
    registers: [Register; REGISTERS_COUNT],
    memory: Vec<MemoryCell>,
    pc: u32,
    gas_counter: UnsignedGas,
    code: Octets,
    jump_table: Vec<u32>,
    opcode_bitmask: Vec<u8>,
}

struct Register {
    value: u32,
}

struct MemoryCell {
    value: u8,
    access: AccessType,
    status: CellStatus,
}

enum AccessType {
    ReadOnly,
    ReadWrite,
    Inaccessible,
}

enum CellStatus {
    Readable,
    Writable,
    Unavailable,
}

impl PVM {
    pub(crate) fn initialize(program: Octets, args: Octets) -> Result<Self, VMError> {
        todo!()
    }

    fn decode_program(program: Octets) -> Result<StandardProgram, VMError> {
        StandardProgram::decode(&mut program.as_slice()).map_err(|e| VMError::JamCodecError(e))
    }
}

struct StandardProgram {
    read_only_length: u32,      // |o|
    read_write_length: u32,     // |w|
    jump_table_entry_size: u16, // z
    stack_size: u32,            // s
    read_only_data: Octets,     // o
    read_write_data: Octets,    // w
    code_length: u32,           // |c|
    code: Octets,               // c
}

impl JamDecode for StandardProgram {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let read_only_length = u32::decode_fixed(input, 3)?;
        let read_write_length = u32::decode_fixed(input, 3)?;
        let jump_table_entry_size = u16::decode_fixed(input, 2)?;
        let stack_size = u32::decode_fixed(input, 3)?;
        let read_only_data = Octets::decode_fixed(input, read_only_length as usize)?;
        let read_write_data = Octets::decode_fixed(input, read_write_length as usize)?;
        let code_length = u32::decode_fixed(input, 4)?;
        let code = Octets::decode_fixed(input, code_length as usize)?;

        Ok(Self {
            read_only_length,
            read_write_length,
            jump_table_entry_size,
            stack_size,
            read_only_data,
            read_write_data,
            code_length,
            code,
        })
    }
}
