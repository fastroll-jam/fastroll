use thiserror::Error;
use crate::constants::REGISTERS_COUNT;
use jam_common::{Octets, UnsignedGas};

/// Polka Virtual Machine

#[derive(Debug, Error)]
enum VMError {
    OutOfGas,
    InvalidProgramCounter,
    MemoryAccessViolation,
    MemoryUnavailable,
    Halt,
    InvalidProgram,
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

struct MemoryCell {
    value: u8,
    access: AccessType,
    status: CellStatus,
}
