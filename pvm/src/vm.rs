use crate::constants::{
    INPUT_SIZE, MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT, SEGMENT_SIZE, STANDARD_PROGRAM_SIZE_LIMIT,
};
use jam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamInput};
use jam_common::{Octets, UnsignedGas};
use thiserror::Error;

// PVM Error Codes
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

// Enums
#[derive(Clone, Copy, Default)]
enum AccessType {
    #[default]
    ReadOnly,
    ReadWrite,
    Inaccessible,
}

#[derive(Clone, Copy, Default)]
enum CellStatus {
    #[default]
    Readable,
    Writable,
    Unavailable,
}

enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault,
    HostCall,
}

enum CommonInvocationResult {
    OutOfGas(ExitReason, InvocationContext), // (exit_reason, context)
    Result(UnsignedGas, Octets),             // (posterior_gas, return_value)
    ResultUnavailable(UnsignedGas),          // (posterior_gas, [])
    Failure(ExitReason, InvocationContext),  // (panic, context)
}

#[allow(non_camel_case_types)]
enum InvocationContext {
    X_I, // Is-Authorized
    X_R, // Refine
    X_A, // Accumulate
    X_T, // On-Transfer
}

// Structs
struct PVM {
    registers: [Register; REGISTERS_COUNT], // omega
    memory: Memory,                         // mu
    pc: u32,                                // iota
    gas_counter: UnsignedGas,               // xi
    program_code: Octets,                   // p (`c` of the Initialization Decoder Function `Y`)
    instructions: Octets,                   // c
    jump_table: Vec<u32>,                   // j
    opcode_bitmask: Octets,                 // k TODO: type check
}

#[derive(Clone, Copy)]
struct Register {
    value: u32,
}

struct Memory {
    cells: Vec<MemoryCell>,
    page_size: usize,
}

#[derive(Clone, Copy, Default)]
struct MemoryCell {
    value: u8,
    access: AccessType,
    status: CellStatus,
}

struct FormattedProgram {
    read_only_len: u32,      // |o|
    read_write_len: u32,     // |w|
    extra_heap_pages: u16,   // z
    stack_size: u32,         // s
    read_only_data: Octets,  // o
    read_write_data: Octets, // w
    code_len: u32,           // |c|
    code: Octets,            // c
}

// Helper functions for the standard program initialization
fn p(x: usize) -> usize {
    // P(x) = Z_P * ceil(x / Z_P)
    PAGE_SIZE * ((x + PAGE_SIZE - 1) / PAGE_SIZE)
}

fn q(x: usize) -> usize {
    // Q(x) = Z_Q * ceil(x / Z_Q)
    SEGMENT_SIZE * ((x + SEGMENT_SIZE - 1) / SEGMENT_SIZE)
}

impl Default for PVM {
    fn default() -> Self {
        Self {
            registers: [Register { value: 0 }; REGISTERS_COUNT],
            memory: Memory::new(0, 0),
            pc: 0,
            gas_counter: 0,
            program_code: vec![],
            instructions: vec![],
            jump_table: vec![],
            opcode_bitmask: vec![],
        }
    }
}

impl PVM {
    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &Octets) -> Result<(), VMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only data area (o)
        let o_start = SEGMENT_SIZE; // Z_Q
        let o_end = o_start + fp.read_only_len as usize;
        memory.set_range(o_start, &fp.read_only_data[..], AccessType::ReadOnly);
        memory.set_access_range(
            o_end,
            SEGMENT_SIZE + p(fp.read_only_len as usize),
            AccessType::ReadOnly,
        );

        // Read-write (heap) data (w)
        let w_start = 2 * SEGMENT_SIZE + q(fp.read_only_len as usize);
        let w_end = w_start + fp.read_write_len as usize;
        memory.set_range(w_start, &fp.read_write_data[..], AccessType::ReadWrite);
        let heap_end = w_end + p(fp.read_write_len as usize) - fp.read_write_len as usize
            + fp.extra_heap_pages as usize * PAGE_SIZE;
        memory.set_access_range(w_end, heap_end, AccessType::ReadWrite);

        // Stack (s)
        let stack_start = (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE - p(fp.stack_size as usize);
        let stack_end = (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE;
        memory.set_access_range(stack_start, stack_end, AccessType::ReadWrite);

        // Arguments
        let args_start = (1 << 32) - SEGMENT_SIZE - INPUT_SIZE;
        let args_end = args_start + args.len();
        memory.set_range(args_start, &args[..], AccessType::ReadOnly);
        memory.set_access_range(
            args_end,
            (1 << 32) - SEGMENT_SIZE - INPUT_SIZE + p(args.len()),
            AccessType::ReadOnly,
        );

        // Other addresses are inaccessible
        memory.set_access_range(0, SEGMENT_SIZE, AccessType::Inaccessible);
        memory.set_access_range(heap_end, stack_start, AccessType::Inaccessible);
        memory.set_access_range(stack_end, args_start, AccessType::Inaccessible);

        self.memory = memory;
        Ok(())
    }

    fn initialize_registers(&mut self, args_len: usize) {
        self.registers[1].value = u32::MAX - (1 << 16) + 1;
        self.registers[2].value = u32::MAX - (2 * SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.registers[10].value = u32::MAX - (SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.registers[11].value = args_len as u32;
    }

    // Decode program blob into formatted program
    fn decode_standard_program(program: Octets) -> Result<FormattedProgram, VMError> {
        FormattedProgram::decode(&mut program.as_slice()).map_err(VMError::JamCodecError)
    }

    // Decode program code into instruction sequence, dynamic jump table, and opcode bitmask
    fn decode_program_code(code: Octets) -> Result<(Octets, Octets, Vec<u16>), VMError> {
        let mut input = code.as_slice();

        // TODO: type check
        // Decode |j| (length of the jump table)
        let jump_table_len = usize::decode(&mut input)?;

        // Decode z (jump table entry length in octets)
        let z = u8::decode_fixed(&mut input, 1)?;

        // Decode |c| (length of the instruction sequence)
        let instructions_len = usize::decode(&mut input)?;

        // Decode the dynamic jump table (j)
        let mut jump_table = Vec::with_capacity(jump_table_len);
        for _ in 0..jump_table_len {
            jump_table.push(u16::decode_fixed(&mut input, z as usize)?);
        }

        // Decode the instruction sequence (c)
        let instructions = Octets::decode_fixed(&mut input, instructions_len)?;

        // Decode the opcode bitmask (k)
        // The length of `k` must be equivalent to the length of `c`, |k| = |c|
        let opcode_bitmask = Octets::decode_fixed(&mut input, instructions_len)?;

        if !input.is_empty() {
            return Err(VMError::InvalidProgram);
        }

        Ok((instructions, opcode_bitmask, jump_table))
    }

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represented as `Y` in the GP
    fn new_from_standard_program(standard_program: Octets, args: Octets) -> Result<Self, VMError> {
        let mut pvm = PVM::default();

        // decode program and check validity
        let formatted_program = Self::decode_standard_program(standard_program)?;
        if !formatted_program.check_size_limit() {
            return Err(VMError::InvalidProgram);
        }

        pvm.setup_memory_layout(&formatted_program, &args)?;
        pvm.initialize_registers(args.len());
        pvm.program_code = formatted_program.code;

        Ok(pvm)
    }

    /// Invoke the PVM with program and arguments
    /// This works as a common interface for 4 different PVM invocations
    ///
    /// Represented as `Psi_M` in the GP
    pub(crate) fn common_invocation(
        standard_program: Octets,
        args: Octets,
    ) -> Result<CommonInvocationResult, VMError> {
        let pvm = Self::new_from_standard_program(standard_program, args)?;

        // TODO: host-call extended PVM invocation
        todo!()
    }
}

impl Memory {
    fn new(size: usize, page_size: usize) -> Self {
        let cells = vec![MemoryCell::default(); size];
        Memory { cells, page_size }
    }

    /// Set memory cells of provided range with data and access type
    fn set_range(&mut self, start: usize, data: &[u8], access: AccessType) {
        for (i, &byte) in data.iter().enumerate() {
            if let Some(cell) = self.cells.get_mut(start + i) {
                cell.value = byte;
                cell.access = access;
                cell.status = match access {
                    AccessType::ReadOnly => CellStatus::Readable,
                    AccessType::ReadWrite => CellStatus::Writable,
                    AccessType::Inaccessible => CellStatus::Unavailable,
                };
            }
        }
    }

    /// Set memory cells of provided range with access type
    fn set_access_range(&mut self, start: usize, end: usize, access: AccessType) {
        for cell in &mut self.cells[start..end] {
            cell.status = match access {
                AccessType::ReadOnly => CellStatus::Readable,
                AccessType::ReadWrite => CellStatus::Writable,
                AccessType::Inaccessible => CellStatus::Unavailable,
            };
        }
    }
}

impl JamDecode for FormattedProgram {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let read_only_len = u32::decode_fixed(input, 3)?;
        let read_write_len = u32::decode_fixed(input, 3)?;
        let extra_heap_pages = u16::decode_fixed(input, 2)?;
        let stack_size = u32::decode_fixed(input, 3)?;
        let read_only_data = Octets::decode_fixed(input, read_only_len as usize)?;
        let read_write_data = Octets::decode_fixed(input, read_write_len as usize)?;
        let code_len = u32::decode_fixed(input, 4)?;
        let code = Octets::decode_fixed(input, code_len as usize)?;

        Ok(Self {
            read_only_len,
            read_write_len,
            extra_heap_pages,
            stack_size,
            read_only_data,
            read_write_data,
            code_len,
            code,
        })
    }
}

impl FormattedProgram {
    fn check_size_limit(&self) -> bool {
        let condition_value = 5 * SEGMENT_SIZE
            + q(self.read_only_len as usize)
            + q(self.read_write_len as usize + (self.extra_heap_pages as usize) * PAGE_SIZE)
            + q(self.stack_size as usize)
            + INPUT_SIZE;
        condition_value <= STANDARD_PROGRAM_SIZE_LIMIT
    }
}
