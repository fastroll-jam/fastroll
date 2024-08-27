use crate::constants::{
    INPUT_SIZE, MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT, SEGMENT_SIZE, STANDARD_PROGRAM_SIZE_LIMIT,
};
use bit_vec::BitVec;
use jam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamEncodeFixed, JamInput};
use jam_common::{Octets, UnsignedGas};
use thiserror::Error;

type MemAddress = u32;

/// PVM Error Codes
#[derive(Debug, Error)]
pub(crate) enum VMError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Invalid program counter value")]
    InvalidProgramCounter,
    #[error("Memory access violation: {0}")]
    MemoryAccessViolation(MemAddress),
    #[error("Memory cell unavailable: {0}")]
    MemoryUnavailable(MemAddress),
    #[error("Panic")]
    Panic,
    #[error("Invalid program")]
    InvalidProgram,
    #[error("Invalid instruction format")]
    InvalidInstructionFormat,
    #[error("Invalid immediate value")]
    InvalidImmediateValue,
    #[error("Invalid host call type")]
    InvalidHostCallType,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// PVM Opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
enum Opcode {
    TRAP = 0,
    LOAD_IND_U32 = 1,
    ADD_IMM = 2,
    STORE_IND_U32 = 3,
    LOAD_IMM = 4,
    JUMP = 5,
    LOAD_IMM_JUMP = 6,
    BRANCH_EQ_IMM = 7,
    ADD = 8,
    SHLO_L_IMM = 9,
    LOAD_U32 = 10,
    LOAD_IND_U8 = 11,
    OR = 12,
    STORE_IMM_IND_U32 = 13,
    SHLO_R_IMM = 14,
    BRANCH_NE_IMM = 15,
    STORE_IND_U8 = 16,
    FALLTHROUGH = 17,
    AND_IMM = 18,
    JUMP_IND = 19,
    SUB = 20,
    LOAD_IND_I8 = 21,
    STORE_U32 = 22,
    AND = 23,
    BRANCH_EQ = 24,
    SHAR_R_IMM = 25,
    STORE_IMM_IND_U8 = 26,
    SET_LT_U_IMM = 27,
    XOR = 28,
    STORE_IND_U16 = 29,
    BRANCH_NE = 30,
    XOR_IMM = 31,
    BRANCH_LT_S_IMM = 32,
    LOAD_IND_I16 = 33,
    MUL = 34,
    MUL_IMM = 35,
    SET_LT_U = 36,
    LOAD_IND_U16 = 37,
    STORE_IMM_U32 = 38,
    SET_GT_U_IMM = 39,
    NEG_ADD_IMM = 40,
    BRANCH_GE_U = 41,
    LOAD_IMM_JUMP_IND = 42,
    BRANCH_GE_S = 43,
    BRANCH_LT_U_IMM = 44,
    BRANCH_GE_S_IMM = 45,
    BRANCH_LE_S_IMM = 46,
    BRANCH_LT_U = 47,
    BRANCH_LT_S = 48,
    OR_IMM = 49,
    BRANCH_GT_U_IMM = 50,
    SHLO_R = 51,
    BRANCH_GE_U_IMM = 52,
    BRANCH_GT_S_IMM = 53,
    STORE_IMM_IND_U16 = 54,
    SHLO_L = 55,
    SET_LT_S_IMM = 56,
    MUL_UPPER_UU = 57,
    SET_LT_S = 58,
    BRANCH_LE_U_IMM = 59,
    LOAD_U8 = 60,
    SET_GT_S_IMM = 61,
    STORE_IMM_U8 = 62,
    MUL_UPPER_UU_IMM = 63,
    DIV_S = 64,
    MUL_UPPER_SS_IMM = 65,
    LOAD_I16 = 66,
    MUL_UPPER_SS = 67,
    DIV_U = 68,
    STORE_U16 = 69,
    REM_S = 70,
    STORE_U8 = 71,
    SHLO_R_IMM_ALT = 72,
    REM_U = 73,
    LOAD_I8 = 74,
    SHLO_L_IMM_ALT = 75,
    LOAD_U16 = 76,
    SHAR_R = 77,
    ECALLI = 78,
    STORE_IMM_U16 = 79,
    SHAR_R_IMM_ALT = 80,
    MUL_UPPER_SU = 81,
    MOVE_REG = 82,
    CMOV_IZ = 83,
    CMOV_NZ = 84,
    CMOV_IZ_IMM = 85,
    CMOV_NZ_IMM = 86,
    SBRK = 87,
}

impl Opcode {
    pub fn from_u8(value: u8) -> Option<Self> {
        if value <= 87 {
            Some(unsafe { std::mem::transmute(value) })
        } else {
            None
        }
    }
}

//
// Enums
//

#[derive(Clone, Copy, Default)]
enum AccessType {
    #[default]
    ReadOnly,
    ReadWrite,
    Inaccessible,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
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
    HostCall(HostCallType),
}

#[repr(u8)]
#[allow(non_camel_case_types)]
enum HostCallType {
    // General Functions
    GAS = 0,
    LOOKUP = 1,
    READ = 2,
    WRITE = 3,
    INFO = 4,
    // Accumulate Functions
    EMPOWER = 5,
    ASSIGN = 21, // TODO: check value
    DESIGNATE = 6,
    CHECKPOINT = 7,
    NEW = 22, // TODO: check value
    UPGRADE = 8,
    TRANSFER = 9,
    QUIT = 10,
    SOLICIT = 11,
    FORGET = 12,
    // Refine Functions
    HISTORICAL_LOOKUP = 13,
    IMPORT = 14,
    EXPORT = 15,
    MACHINE = 16,
    PEEK = 17,
    POKE = 18,
    INVOKE = 19,
    EXPUNGE = 20,
}

impl HostCallType {
    pub fn from_u8(value: u8) -> Option<Self> {
        if value <= 22 {
            Some(unsafe { std::mem::transmute(value) })
        } else {
            None
        }
    }
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

//
// Structs
//

/// Main stateful PVM struct
struct PVM {
    state: VMState,
    program: Program,
}

/// Mutable VM state
#[derive(Clone)]
struct VMState {
    registers: [Register; REGISTERS_COUNT], // omega
    memory: Memory,                         // mu
    pc: MemAddress,                         // iota
    gas_counter: UnsignedGas,               // xi
}

/// Immutable program components
struct Program {
    program_code: Octets, // p (`c` of the Initialization Decoder Function `Y`)
    instructions: Octets, // c; serialized
    jump_table: Vec<MemAddress>, // j
    opcode_bitmask: BitVec, // k
}

#[derive(Clone, Copy)]
struct Register {
    value: u32,
}

#[derive(Clone)]
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

#[derive(Debug)]
struct Instruction {
    op: Opcode,          // opcode
    r1: Option<u8>,      // first source register
    r2: Option<u8>,      // second source register
    rd: Option<u8>,      // destination register
    imm1: Option<u32>,   // first immediate value argument
    imm2: Option<u32>,   // second immediate value argument
    offset: Option<i32>, // offset argument
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

struct StateChange {
    register_changes: Vec<(usize, u32)>,
    memory_changes: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pc_change: Option<MemAddress>,
    gas_change: UnsignedGas,
    exit_reason: ExitReason,
}

//
// Helper functions for the standard program initialization
//

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
            state: VMState {
                registers: [Register { value: 0 }; REGISTERS_COUNT],
                memory: Memory::new(0, 0),
                pc: 0,
                gas_counter: 0,
            },
            program: Program {
                program_code: vec![],
                instructions: vec![],
                jump_table: vec![],
                opcode_bitmask: BitVec::new(),
            },
        }
    }
}

impl PVM {
    fn charge_gas(&mut self, amount: UnsignedGas) -> Result<(), VMError> {
        if self.state.gas_counter < amount {
            Err(VMError::OutOfGas)
        } else {
            self.state.gas_counter -= amount;
            Ok(())
        }
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), VMError> {
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

        self.state.memory = memory;
        Ok(())
    }

    fn initialize_registers(&mut self, args_len: usize) {
        self.state.registers[1].value = u32::MAX - (1 << 16) + 1;
        self.state.registers[2].value = u32::MAX - (2 * SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[10].value = u32::MAX - (SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[11].value = args_len as u32;
    }

    /// Decode program blob into formatted program
    fn decode_standard_program(program: &[u8]) -> Result<FormattedProgram, VMError> {
        let mut input = program;
        FormattedProgram::decode(&mut input).map_err(VMError::JamCodecError)
    }

    /// Decode program code into instruction sequence, opcode bitmask and dynamic jump table
    fn decode_program_code(code: &[u8]) -> Result<(Octets, BitVec, Vec<MemAddress>), VMError> {
        let mut input = code;

        // Decode the length of the jump table (|j|)
        let jump_table_len = usize::decode(&mut input)?;

        // Decode the jump table entry length in octets (z)
        let z = u8::decode_fixed(&mut input, 1)?;

        // Decode the length of the instruction sequence (|c|)
        let instructions_len = usize::decode(&mut input)?;

        // Decode the dynamic jump table (j)
        let mut jump_table = Vec::with_capacity(jump_table_len);
        for _ in 0..jump_table_len {
            jump_table.push(MemAddress::decode_fixed(&mut input, z as usize)?);
        }

        // Decode the instruction sequence (c)
        let instructions = Octets::decode_fixed(&mut input, instructions_len)?;

        // Decode the opcode bitmask (k)
        // The length of `k` must be equivalent to the length of `c`, |k| = |c|
        let opcode_bitmask = BitVec::decode_fixed(&mut input, instructions_len)?;

        if !input.is_empty() {
            return Err(VMError::InvalidProgram);
        }

        Ok((instructions, opcode_bitmask, jump_table))
    }

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represented as `Y` in the GP
    fn new_from_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, VMError> {
        let mut pvm = PVM::default();

        // decode program and check validity
        let formatted_program = Self::decode_standard_program(standard_program)?;
        if !formatted_program.check_size_limit() {
            return Err(VMError::InvalidProgram);
        }

        pvm.setup_memory_layout(&formatted_program, &args)?;
        pvm.initialize_registers(args.len());
        pvm.program.program_code = formatted_program.code;

        Ok(pvm)
    }

    /// Invoke the PVM with program and arguments
    /// This works as a common interface for 4 different PVM invocations
    ///
    /// Represented as `Psi_M` in the GP
    pub(crate) fn common_invocation(
        standard_program: &[u8],
        args: &[u8],
        pc: MemAddress,
        gas: UnsignedGas,
        host_function: u32, // TODO: type
        context: InvocationContext,
    ) -> Result<CommonInvocationResult, VMError> {
        let pvm = Self::new_from_standard_program(standard_program, args)?;

        // host-call extended PVM invocation
        todo!()
    }

    /// Invoke the PVM general functions including host calls with arguments injected by the `Psi_M`
    /// common invocation function
    ///
    /// Represented as `Psi_H` in the GP
    fn extended_invocation(program_code: &[u8]) -> Result<ExitReason, VMError> {
        todo!()
    }

    /// Recursively call single-step invocation functions following the instruction sequence
    ///
    /// Represented as `Psi` in the GP
    fn general_invocation() {}

    /// Single-step invocation to return PVM state mutations by each instruction rules
    ///
    /// Represented as `Psi_1` in the GP
    fn single_step_invocation() {}

    //
    // PVM Instruction functions
    //

    //
    // Group 1: Instructions without Arguments
    //

    /// `panic` with no mutation to the VM state
    ///
    /// Opcode: 0
    fn trap() -> Result<StateChange, VMError> {
        Ok(StateChange {
            exit_reason: ExitReason::Panic,
            ..Default::default()
        })
    }

    /// Continue program with no mutation to the VM state
    ///
    /// Opcode: 17
    fn fallthrough() -> Result<StateChange, VMError> {
        Ok(StateChange::default())
    }

    //
    // Group 2: Instructions with Arguments of One Immediate
    //

    /// Invoke host function call
    ///
    /// Opcode: 78
    fn ecalli(ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_host_call_type =
            u8::try_from(ins.imm1.unwrap()).map_err(|_| VMError::InvalidImmediateValue)?;

        let exit_reason = HostCallType::from_u8(imm_host_call_type)
            .ok_or(VMError::InvalidHostCallType)
            .map(ExitReason::HostCall)?;

        Ok(StateChange {
            exit_reason,
            ..Default::default()
        })
    }

    //
    // Group 3: Instructions with Arguments of Two Immediates
    //

    /// Store immediate argument value to the memory as `u8` integer type
    ///
    /// Opcode: 62
    fn store_imm_u8(ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = vec![(imm_value & 0xFF) as u8]; // mod 2^8

        Ok(StateChange {
            memory_changes: (imm_address, value, 1),
            ..Default::default()
        })
    }

    /// Store immediate argument value to the memory as `u16` integer type
    ///
    /// Opcode: 79
    fn store_imm_u16(ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = ((imm_value & 0xFFFF) as u16).encode_fixed(2)?; // mod 2^16

        Ok(StateChange {
            memory_changes: (imm_address, value, 2),
            ..Default::default()
        })
    }

    /// Store immediate argument value to the memory as `u32` integer type
    ///
    /// Opcode: 38
    fn store_imm_u32(ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = imm_value.encode_fixed(4)?;

        Ok(StateChange {
            memory_changes: (imm_address, value, 4),
            ..Default::default()
        })
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

    /// Read a byte from memory
    fn read_u8(&self, address: MemAddress) -> Result<u8, VMError> {
        let cell = self
            .cells
            .get(address as usize)
            .ok_or(VMError::MemoryAccessViolation(address))?;

        match cell.status {
            CellStatus::Readable | CellStatus::Writable => Ok(cell.value),
            CellStatus::Unavailable => Err(VMError::MemoryUnavailable(address)),
        }
    }

    /// Write an u8 value to memory
    fn write_u8(&mut self, address: MemAddress, value: u8) -> Result<(), VMError> {
        let cell = self
            .cells
            .get_mut(address as usize)
            .ok_or(VMError::MemoryAccessViolation(address))?;

        match cell.status {
            CellStatus::Writable => {
                cell.value = value;
                Ok(())
            }
            CellStatus::Readable | CellStatus::Unavailable => {
                Err(VMError::MemoryUnavailable(address))
            }
        }
    }

    /// Read two consecutive bytes from memory
    pub fn read_u16(&self, address: MemAddress) -> Result<u16, VMError> {
        let b0 = self.read_u8(address)?;
        let b1 = self.read_u8(address.wrapping_add(1))?;
        Ok(u16::from_le_bytes([b0, b1]))
    }

    /// Write an u16 value as two consecutive bytes to memory
    pub fn write_u16(&mut self, address: MemAddress, value: u16) -> Result<(), VMError> {
        let [b0, b1] = value.to_le_bytes();
        self.write_u8(address, b0)?;
        self.write_u8(address.wrapping_add(1), b1)?;
        Ok(())
    }

    /// Read four consecutive bytes from memory
    pub fn read_u32(&self, address: MemAddress) -> Result<u32, VMError> {
        let b0 = self.read_u8(address)?;
        let b1 = self.read_u8(address.wrapping_add(1))?;
        let b2 = self.read_u8(address.wrapping_add(2))?;
        let b3 = self.read_u8(address.wrapping_add(3))?;
        Ok(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    /// Write an u32 value as four consecutive bytes to memory
    pub fn write_u32(&mut self, address: MemAddress, value: u32) -> Result<(), VMError> {
        let [b0, b1, b2, b3] = value.to_le_bytes();
        self.write_u8(address, b0)?;
        self.write_u8(address.wrapping_add(1), b1)?;
        self.write_u8(address.wrapping_add(2), b2)?;
        self.write_u8(address.wrapping_add(3), b3)?;
        Ok(())
    }

    /// Read a specified number of bytes from memory starting at the given address
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, VMError> {
        (0..length)
            .map(|i| self.read_u8(address + i as MemAddress))
            .collect()
    }

    /// Write a slice of bytes to memory starting at the given address
    pub fn write_bytes(&mut self, address: MemAddress, bytes: &[u8]) -> Result<(), VMError> {
        for (i, &byte) in bytes.iter().enumerate() {
            self.write_u8(address + i as MemAddress, byte)?;
        }
        Ok(())
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

impl Instruction {
    fn new(
        op: Opcode,
        r1: Option<u8>,
        r2: Option<u8>,
        rd: Option<u8>,
        imm1: Option<u32>,
        imm2: Option<u32>,
        offset: Option<i32>,
    ) -> Result<Self, VMError> {
        // Validate register indices
        for &reg in [rd, r1, r2].iter().flatten() {
            if reg > (REGISTERS_COUNT - 1) as u8 {
                return Err(VMError::InvalidInstructionFormat);
            }
        }

        Ok(Self {
            op,
            r1,
            r2,
            rd,
            imm1,
            imm2,
            offset,
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

impl Default for StateChange {
    fn default() -> Self {
        Self {
            register_changes: vec![],
            memory_changes: (0, vec![], 0),
            pc_change: None,
            gas_change: 0,
            exit_reason: ExitReason::Continue,
        }
    }
}
