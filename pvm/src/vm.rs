use crate::{
    constants::{
        INPUT_SIZE, JUMP_ALIGNMENT, MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT, SEGMENT_SIZE,
        STANDARD_PROGRAM_SIZE_LIMIT,
    },
    host::{HostCallStateChange, HostCallType, HostFunction, InvocationContext},
    opcode::Opcode,
};
use bit_vec::BitVec;
use jam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamEncodeFixed, JamInput};
use jam_common::{Octets, UnsignedGas};
use std::cmp::{max, min};
use thiserror::Error;

pub(crate) type MemAddress = u32;

/// PVM Error Codes
#[derive(Debug, Error)]
pub(crate) enum VMError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Out of memory")]
    OutOfMemory,
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
    #[error("Invalid opcode")]
    InvalidOpcode,
    #[error("Invalid immediate value")]
    InvalidImmediateValue,
    #[error("Invalid host call type")]
    InvalidHostCallType,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

//
// Enums
//

/// Memory Cell Access Types
#[derive(Clone, Copy, Default)]
enum AccessType {
    #[default]
    ReadOnly,
    ReadWrite,
    Inaccessible,
}

/// Memory Cell Statuses
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum CellStatus {
    #[default]
    Readable,
    Writable,
    Unavailable,
}

/// PVM Invocation Exit Reasons
pub(crate) enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault(MemAddress),
    HostCall(HostCallType),
}

enum ExecutionResult {
    Complete(ExitReason),
    HostCall(HostCallType),
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

//
// Structs
//

struct ProgramDecoder;

/// Main stateful PVM struct
struct PVM {
    state: VMState,
    program: Program,
}

/// Mutable VM state
#[derive(Clone)]
pub(crate) struct VMState {
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
    basic_block_bitmask: BitVec, // bitmask to detect opcode addresses that begin basic blocks
}

#[derive(Clone, Copy)]
pub(crate) struct Register {
    value: u32,
}

#[derive(Clone)]
struct Memory {
    cells: Vec<MemoryCell>,
    page_size: usize,
    heap_start: MemAddress,
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
    r1: Option<usize>,   // first source register index
    r2: Option<usize>,   // second source register index
    rd: Option<usize>,   // destination register index
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
    memory_change: (MemAddress, Octets, u32), // (start_address, data, data_len)
    pc_change: Option<MemAddress>,
    gas_change: UnsignedGas,
    exit_reason: ExitReason, // TODO: check if necessary
}

struct VMUtils;

impl ProgramDecoder {
    //
    // Program decoding functions
    //

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

    /// Extracts and processes an immediate value from the instruction blob.
    fn extract_imm_value(
        inst_blob: &[u8],
        l_x: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<u32, VMError> {
        if l_x > 0 {
            let mut buffer = [0u8; 4];
            buffer[..l_x].copy_from_slice(&inst_blob[start_index..end_index]);
            Ok(
                VMUtils::signed_extend(l_x as u32, u32::decode_fixed(&mut &buffer[..l_x], l_x)?)
                    .unwrap(),
            )
        } else {
            Ok(0)
        }
    }

    /// Extracts and processes an immediate address (pc increment) value from the instruction blob.
    fn extract_imm_address(
        pc: MemAddress,
        inst_blob: &[u8],
        l_y: usize,
        start_index: usize,
        end_index: usize,
    ) -> Result<i32, VMError> {
        let pc_increment = if l_y > 0 {
            let mut buffer = [0u8; 4];
            buffer[..l_y].copy_from_slice(&inst_blob[start_index..end_index]);
            VMUtils::unsigned_to_signed(l_y as u32, u32::decode_fixed(&mut &buffer[..l_y], l_y)?)
                .unwrap()
        } else {
            0
        };

        Ok(pc as i32 + pc_increment)
    }

    /// Decodes a single instruction blob into an `Instruction` type.
    ///
    /// This function takes a byte slice representing an instruction and converts it
    /// into a more easily consumable `Instruction` type, which can be used by
    /// single-step PVM state-transition functions.
    ///
    /// The instruction blob should not exceed 16 bytes in length.
    /// The opcode is represented by the first byte of the instruction blob.
    fn decode_instruction(
        mut inst_blob: &[u8],
        current_pc: MemAddress,
        skip_distance: usize,
    ) -> Result<Instruction, VMError> {
        use Opcode::*;
        let op = Opcode::from_u8(inst_blob[0]).ok_or(VMError::InvalidOpcode)?;

        match op {
            // Group 1: no arguments
            TRAP | FALLTHROUGH => Ok(Instruction::new(op, None, None, None, None, None, None)?),

            // Group 2: one immediate
            ECALLI => {
                let l_x = min(4, skip_distance);
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 1, 1 + l_x)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 3: two immediates
            STORE_IMM_U8 | STORE_IMM_U16 | STORE_IMM_U32 => {
                let l_x = min(4, inst_blob[1] % 8) as usize;
                let l_y = min(4, max(0, skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 4: one offset
            JUMP => {
                let l_x = min(4, skip_distance);
                let imm_x = Self::extract_imm_address(current_pc, inst_blob, l_x, 1, 1 + l_x)?;

                Ok(Instruction::new(
                    op,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(imm_x),
                )?)
            }

            // Group 5: one register & one immediate
            JUMP_IND | LOAD_IMM | LOAD_U8 | LOAD_I8 | LOAD_U16 | LOAD_I16 | LOAD_U32 | STORE_U8
            | STORE_U16 | STORE_U32 => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = min(4, max(0, skip_distance - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 6: one register & two immediates
            STORE_IMM_IND_U8 | STORE_IMM_IND_U16 | STORE_IMM_IND_U32 => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = min(
                    4,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8 % 8,
                ) as usize;
                let l_y = min(4, max(0, skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 7: one register, one immediate and one offset
            LOAD_IMM_JUMP | BRANCH_EQ_IMM | BRANCH_NE_IMM | BRANCH_LT_U_IMM | BRANCH_LE_U_IMM
            | BRANCH_GE_U_IMM | BRANCH_GT_U_IMM | BRANCH_LT_S_IMM | BRANCH_LE_S_IMM
            | BRANCH_GE_S_IMM | BRANCH_GT_S_IMM => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let l_x = min(
                    4,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8 % 8,
                ) as usize;
                let l_y = min(4, max(0, skip_distance - l_x - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;
                let imm_y =
                    Self::extract_imm_address(current_pc, inst_blob, l_y, 2 + l_x, 2 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    None,
                    Some(imm_x),
                    None,
                    Some(imm_y),
                )?)
            }

            // Group 8: two registers
            MOVE_REG | SBRK => {
                let r_d = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_a = min(
                    12,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8,
                ) as usize;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    None,
                    Some(r_d),
                    None,
                    None,
                    None,
                )?)
            }

            // Group 9: two register & one immediate
            STORE_IND_U8 | STORE_IND_U16 | STORE_IND_U32 | LOAD_IND_U8 | LOAD_IND_I8
            | LOAD_IND_U16 | LOAD_IND_I16 | LOAD_IND_U32 | ADD_IMM | AND_IMM | XOR_IMM | OR_IMM
            | MUL_IMM | MUL_UPPER_SS_IMM | MUL_UPPER_UU_IMM | SET_LT_U_IMM | SET_LT_S_IMM
            | SHLO_L_IMM | SHLO_R_IMM | SHAR_R_IMM | NEG_ADD_IMM | SET_GT_U_IMM | SET_GT_S_IMM
            | SHLO_L_IMM_ALT | SHLO_R_IMM_ALT | SHAR_R_IMM_ALT | CMOV_IZ_IMM | CMOV_NZ_IMM => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = min(
                    12,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8,
                ) as usize;
                let l_x = min(4, max(0, skip_distance - 1));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    None,
                    None,
                )?)
            }

            // Group 10: two registers & one offset
            BRANCH_EQ | BRANCH_NE | BRANCH_LT_U | BRANCH_LT_S | BRANCH_GE_U | BRANCH_GE_S => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = min(
                    12,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8,
                ) as usize;
                let l_x = min(4, max(0, skip_distance - 1));
                let imm_x = Self::extract_imm_address(current_pc, inst_blob, l_x, 2, 2 + l_x)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    None,
                    None,
                    Some(imm_x),
                )?)
            }

            // Group 11: two registers & two immediates
            LOAD_IMM_JUMP_IND => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = min(
                    12,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8,
                ) as usize;
                let l_x = min(4, inst_blob[current_pc as usize + 2] % 8) as usize;
                let l_y = min(4, max(0, skip_distance - l_x - 2));
                let imm_x = Self::extract_imm_value(inst_blob, l_x, 3, 3 + l_x)?;
                let imm_y = Self::extract_imm_value(inst_blob, l_y, 3 + l_x, 3 + l_x + l_y)?;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    None,
                    Some(imm_x),
                    Some(imm_y),
                    None,
                )?)
            }

            // Group 12: three registers
            ADD | SUB | AND | XOR | OR | MUL | MUL_UPPER_SS | MUL_UPPER_UU | MUL_UPPER_SU
            | DIV_U | DIV_S | REM_U | REM_S | SET_LT_U | SET_LT_S | SHLO_L | SHLO_R | SHAR_R
            | CMOV_IZ | CMOV_NZ => {
                let r_a = min(12, inst_blob[current_pc as usize + 1] % 16) as usize;
                let r_b = min(
                    12,
                    (inst_blob[current_pc as usize + 1] as f64 / 16.0).floor() as u8,
                ) as usize;
                let r_d = min(12, inst_blob[current_pc as usize + 2]) as usize;

                Ok(Instruction::new(
                    op,
                    Some(r_a),
                    Some(r_b),
                    Some(r_d),
                    None,
                    None,
                    None,
                )?)
            }
        }
    }
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
                basic_block_bitmask: BitVec::new(),
            },
        }
    }
}

impl PVM {
    //
    // VM states initialization
    //

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` in the GP
    fn new_from_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, VMError> {
        let mut pvm = PVM::default();

        // decode program and check validity
        let formatted_program = ProgramDecoder::decode_standard_program(standard_program)?;
        if !formatted_program.check_size_limit() {
            return Err(VMError::InvalidProgram);
        }

        pvm.setup_memory_layout(&formatted_program, &args)?;
        pvm.initialize_registers(args.len());
        pvm.program.program_code = formatted_program.code;

        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), VMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only data area (o)
        let o_start = SEGMENT_SIZE; // Z_Q
        let o_end = o_start + fp.read_only_len as usize;
        memory.set_range(o_start, &fp.read_only_data[..], AccessType::ReadOnly);
        memory.set_access_range(
            o_end,
            SEGMENT_SIZE + VMUtils::p(fp.read_only_len as usize),
            AccessType::ReadOnly,
        );

        // Read-write (heap) data (w)
        let w_start = 2 * SEGMENT_SIZE + VMUtils::q(fp.read_only_len as usize);
        memory.heap_start = w_start as MemAddress;
        let w_end = w_start + fp.read_write_len as usize;
        memory.set_range(w_start, &fp.read_write_data[..], AccessType::ReadWrite);
        let heap_end = w_end + VMUtils::p(fp.read_write_len as usize) - fp.read_write_len as usize
            + fp.extra_heap_pages as usize * PAGE_SIZE;
        memory.set_access_range(w_end, heap_end, AccessType::ReadWrite);

        // Stack (s)
        let stack_start =
            (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE - VMUtils::p(fp.stack_size as usize);
        let stack_end = (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE;
        memory.set_access_range(stack_start, stack_end, AccessType::ReadWrite);

        // Arguments
        let args_start = (1 << 32) - SEGMENT_SIZE - INPUT_SIZE;
        let args_end = args_start + args.len();
        memory.set_range(args_start, &args[..], AccessType::ReadOnly);
        memory.set_access_range(
            args_end,
            (1 << 32) - SEGMENT_SIZE - INPUT_SIZE + VMUtils::p(args.len()),
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

    /// Set `basic_blocks` array of the VM immutable state utilizing instructions blob and opcode bitmask
    fn set_basic_block_bitmask(&mut self) -> Result<(), VMError> {
        let bitmask_len = self.program.opcode_bitmask.len();
        let mut basic_block_bitmask = BitVec::from_elem(bitmask_len, false);

        // MemAddress 0 always starts a basic block
        basic_block_bitmask.set(0, true);

        for n in 0..bitmask_len {
            if self.program.opcode_bitmask.get(n).unwrap() {
                if let Some(op) = Opcode::from_u8(n as u8) {
                    if op.is_termination_opcode() {
                        let basic_block_start_address = n
                            + 1
                            + Self::skip(
                                n as MemAddress,
                                &self.program.instructions,
                                &self.program.opcode_bitmask,
                            );
                        basic_block_bitmask.set(basic_block_start_address, true);
                    }
                }
            }
        }

        self.program.basic_block_bitmask = basic_block_bitmask;
        Ok(())
    }

    //
    // PVM helper functions
    //

    /// Skip function that calculates skip distance to the next instruction from the instruction
    /// sequence and the opcode bitmask
    fn skip(pc: MemAddress, instructions: &[u8], opcode_bitmask: &BitVec) -> usize {
        let mut skip_distance = 0;
        let max_skip = 24;

        // TODO: assertion for instructions.len() == bitmask.len() needed?

        for i in 1..=max_skip {
            let next_opcode_address = pc as usize + i;
            if next_opcode_address >= instructions.len() {
                break;
            }
            if opcode_bitmask[next_opcode_address] {
                skip_distance = i;
                break;
            }
        }

        min(skip_distance, max_skip)
    }

    /// Get the next pc value from the current VM state and the skip function
    /// for normal instruction execution completion
    fn next_pc(&self) -> MemAddress {
        1 + Self::skip(
            self.state.pc,
            &self.program.instructions,
            &self.program.opcode_bitmask,
        ) as MemAddress
    }

    //
    // VM state read functions
    //

    /// Read a byte from memory
    fn read_memory_byte(&self, address: MemAddress) -> Result<u8, VMError> {
        self.state.memory.read_byte(address)
    }

    /// Read a specified number of bytes from memory starting at the given address
    fn read_memory_bytes(&self, address: MemAddress, length: usize) -> Result<Octets, VMError> {
        self.state.memory.read_bytes(address, length)
    }

    /// Read a `u32` value stored in a register of the given index
    fn read_reg(&self, index: usize) -> Result<u32, VMError> {
        Ok(self.state.registers[index].value)
    }

    //
    // VM state mutation functions
    //

    /// Mutate the VM states from the change set produced by single-step instruction execution functions
    fn apply_state_change(&mut self, change: StateChange) -> ExitReason {
        // Apply register changes
        for (reg_index, new_value) in change.register_changes {
            if reg_index < REGISTERS_COUNT {
                self.state.registers[reg_index] = Register { value: new_value };
            } else {
                eprintln!(
                    "Warning: Attempted to change invalid register index: {}",
                    reg_index
                );
            }
        }

        // Apply memory change
        let (start_address, data, data_len) = change.memory_change;
        if data_len as usize <= data.len() {
            for (offset, &byte) in data.iter().take(data_len as usize).enumerate() {
                if let Err(e) = self
                    .state
                    .memory
                    .write_u8(start_address.wrapping_add(offset as u32), byte)
                {
                    eprintln!(
                        "Warning: Failed to write to memory at address {:X}: {:?}",
                        start_address.wrapping_add(offset as u32),
                        e
                    );
                }
            }
        } else {
            eprintln!("Warning: Data length mismatch in memory changes");
        }

        // Apply PC change
        if let Some(new_pc) = change.pc_change {
            self.state.pc = new_pc;
        }

        // Apply gas change
        if self.state.gas_counter >= change.gas_change {
            self.state.gas_counter -= change.gas_change;
        } else {
            return ExitReason::OutOfGas;
        }

        change.exit_reason
    }

    fn apply_host_call_state_change(&mut self, change: HostCallStateChange) -> ExitReason {
        // Apply register changes (register index 0 & 1)
        if let Some(r0) = change.r0_change {
            self.state.registers[0].value = r0;
        }
        if let Some(r1) = change.r1_change {
            self.state.registers[1].value = r1;
        }

        // Apply memory change
        let (start_address, data, data_len) = change.memory_change;
        if data_len as usize <= data.len() {
            for (offset, &byte) in data.iter().take(data_len as usize).enumerate() {
                if let Err(e) = self
                    .state
                    .memory
                    .write_u8(start_address.wrapping_add(offset as u32), byte)
                {
                    eprintln!(
                        "Warning: Failed to write to memory at address {:X}: {:?}",
                        start_address.wrapping_add(offset as u32),
                        e
                    );
                }
            }
        } else {
            eprintln!("Warning: Data length mismatch in memory changes");
        }

        // Apply gas change
        if self.state.gas_counter >= change.gas_change {
            self.state.gas_counter -= change.gas_change;
        } else {
            return ExitReason::OutOfGas;
        }

        change.exit_reason
    }

    //
    // Gas operations
    //

    fn charge_gas(&mut self, amount: UnsignedGas) -> Result<(), VMError> {
        if self.state.gas_counter < amount {
            Err(VMError::OutOfGas)
        } else {
            self.state.gas_counter -= amount;
            Ok(())
        }
    }

    //
    // PVM invocation functions
    //

    /// Invoke the PVM with program and arguments
    /// This works as a common interface for 4 different PVM invocations
    ///
    /// Represents `Psi_M` in the GP
    pub(crate) fn common_invocation(
        standard_program: &[u8],
        pc: MemAddress,
        gas: UnsignedGas,
        args: &[u8],
        context: InvocationContext,
    ) -> Result<CommonInvocationResult, VMError> {
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let mut pvm = Self::new_from_standard_program(standard_program, args)?;
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas;

        // Decode program code into (instructions blob, opcode bitmask, dynamic jump table)
        let (instructions, opcode_bitmask, jump_table) =
            ProgramDecoder::decode_program_code(&pvm.program.program_code)?;

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_bitmask
        pvm.program.instructions = instructions;
        pvm.program.opcode_bitmask = opcode_bitmask;
        pvm.program.jump_table = jump_table;
        pvm.set_basic_block_bitmask()?;

        match pvm.extended_invocation(context)? {
            ExitReason::OutOfGas => Ok(CommonInvocationResult::OutOfGas(
                ExitReason::OutOfGas,
                context,
            )),
            ExitReason::RegularHalt => {
                let result = pvm.read_memory_bytes(pvm.read_reg(10)?, pvm.read_reg(11)? as usize);

                Ok(match result {
                    Ok(bytes) => CommonInvocationResult::Result(pvm.state.gas_counter, bytes),
                    Err(_) => CommonInvocationResult::ResultUnavailable(pvm.state.gas_counter),
                })
            }
            _ => Ok(CommonInvocationResult::Failure(ExitReason::Panic, context)),
        }
    }

    /// Invoke the PVM general functions including host calls with arguments injected by the `Psi_M`
    /// common invocation function
    ///
    /// Represents `Psi_H` in the GP
    fn extended_invocation(&mut self, context: InvocationContext) -> Result<ExitReason, VMError> {
        loop {
            let exit_reason = self.general_invocation()?;

            let state_change = match exit_reason {
                ExitReason::HostCall(h) => match h {
                    HostCallType::GAS => HostFunction::host_gas(
                        self.state.gas_counter,
                        &self.state.registers,
                        context,
                    )?, // TODO: better gas handling
                    // TODO: add other host function cases
                    _ => return Err(VMError::InvalidHostCallType),
                },
                _ => return Ok(exit_reason),
            };
            let host_call_exit_reason = self.apply_host_call_state_change(state_change);
            match host_call_exit_reason {
                ExitReason::PageFault(_address) => return Ok(host_call_exit_reason),
                _ => continue,
            }
        }
    }

    /// Recursively call single-step invocation functions following the instruction sequence
    /// Mutating the VM states
    ///
    /// Represents `Psi` in the GP
    fn general_invocation(&mut self) -> Result<ExitReason, VMError> {
        loop {
            let skip_distance = Self::skip(
                self.state.pc,
                &self.program.instructions,
                &self.program.opcode_bitmask,
            );

            let current_pc = self.state.pc;
            let address = current_pc as usize;
            let next_address = address + 1 + skip_distance;

            // Instruction blob length is not greater than 16
            let instruction_blob = {
                let full_slice = &self.program.instructions[address..next_address];
                if full_slice.len() > 16 {
                    &full_slice[..16]
                } else {
                    full_slice
                }
            };

            // TODO: define instruction_blob with endless zeroes padding
            let ins =
                ProgramDecoder::decode_instruction(&instruction_blob, current_pc, skip_distance)?;

            let state_change = self.single_step_invocation(&ins)?;
            let exit_reason = self.apply_state_change(state_change);
            match exit_reason {
                ExitReason::Continue => continue,
                ExitReason::OutOfGas => return Ok(exit_reason),
                _ => return Ok(exit_reason),
            }
        }
    }

    /// Single-step PVM state transition function
    /// Refers to the VM states e.g. `pc`, `memory`, `instructions` from the `&self` state
    /// and returns the VM state change as an output
    ///
    /// Instruction `SBRK` is the only instruction that directly mutates the VM state, for new heap allocation
    ///
    /// Represents `Psi_1` in the GP
    fn single_step_invocation(&mut self, ins: &Instruction) -> Result<StateChange, VMError> {
        match ins.op {
            Opcode::TRAP => self.trap(),
            Opcode::FALLTHROUGH => self.fallthrough(),
            Opcode::ECALLI => self.ecalli(ins),
            Opcode::STORE_IMM_U8 => self.store_imm_u8(ins),
            Opcode::STORE_IMM_U16 => self.store_imm_u16(ins),
            Opcode::STORE_IMM_U32 => self.store_imm_u32(ins),
            Opcode::JUMP => self.jump(ins),
            Opcode::JUMP_IND => self.jump_ind(ins),
            Opcode::LOAD_IMM => self.load_imm(ins),
            Opcode::LOAD_U8 => self.load_u8(ins),
            Opcode::LOAD_I8 => self.load_i8(ins),
            Opcode::LOAD_U16 => self.load_u16(ins),
            Opcode::LOAD_I16 => self.load_i16(ins),
            Opcode::LOAD_U32 => self.load_u32(ins),
            Opcode::STORE_U8 => self.store_u8(ins),
            Opcode::STORE_U16 => self.store_u16(ins),
            Opcode::STORE_U32 => self.store_u32(ins),
            Opcode::STORE_IMM_IND_U8 => self.store_imm_ind_u8(ins),
            Opcode::STORE_IMM_IND_U16 => self.store_imm_ind_u16(ins),
            Opcode::STORE_IMM_IND_U32 => self.store_imm_ind_u32(ins),
            Opcode::LOAD_IMM_JUMP => self.load_imm_jump(ins),
            Opcode::BRANCH_EQ_IMM => self.branch_eq_imm(ins),
            Opcode::BRANCH_NE_IMM => self.branch_ne_imm(ins),
            Opcode::BRANCH_LT_U_IMM => self.branch_lt_u_imm(ins),
            Opcode::BRANCH_LE_U_IMM => self.branch_le_u_imm(ins),
            Opcode::BRANCH_GE_U_IMM => self.branch_ge_u_imm(ins),
            Opcode::BRANCH_GT_U_IMM => self.branch_gt_u_imm(ins),
            Opcode::BRANCH_LT_S_IMM => self.branch_lt_s_imm(ins),
            Opcode::BRANCH_LE_S_IMM => self.branch_le_s_imm(ins),
            Opcode::BRANCH_GE_S_IMM => self.branch_ge_s_imm(ins),
            Opcode::BRANCH_GT_S_IMM => self.branch_gt_s_imm(ins),
            Opcode::MOVE_REG => self.move_reg(ins),
            Opcode::SBRK => self.sbrk(ins),
            Opcode::STORE_IND_U8 => self.store_ind_u8(ins),
            Opcode::STORE_IND_U16 => self.store_ind_u16(ins),
            Opcode::STORE_IND_U32 => self.store_ind_u32(ins),
            Opcode::LOAD_IND_U8 => self.load_ind_u8(ins),
            Opcode::LOAD_IND_I8 => self.load_ind_i8(ins),
            Opcode::LOAD_IND_U16 => self.load_ind_u16(ins),
            Opcode::LOAD_IND_I16 => self.load_ind_i16(ins),
            Opcode::LOAD_IND_U32 => self.load_ind_u32(ins),
            Opcode::ADD_IMM => self.add_imm(ins),
            Opcode::AND_IMM => self.and_imm(ins),
            Opcode::XOR_IMM => self.xor_imm(ins),
            Opcode::OR_IMM => self.or_imm(ins),
            Opcode::MUL_IMM => self.mul_imm(ins),
            Opcode::MUL_UPPER_SS_IMM => self.mul_upper_s_s_imm(ins),
            Opcode::MUL_UPPER_UU_IMM => self.mul_upper_u_u_imm(ins),
            Opcode::SET_LT_U_IMM => self.set_lt_u_imm(ins),
            Opcode::SET_LT_S_IMM => self.set_lt_s_imm(ins),
            Opcode::SHLO_L_IMM => self.shlo_l_imm(ins),
            Opcode::SHLO_R_IMM => self.shlo_r_imm(ins),
            Opcode::SHAR_R_IMM => self.shar_r_imm(ins),
            Opcode::NEG_ADD_IMM => self.neg_add_imm(ins),
            Opcode::SET_GT_U_IMM => self.set_gt_u_imm(ins),
            Opcode::SET_GT_S_IMM => self.set_gt_s_imm(ins),
            Opcode::SHLO_L_IMM_ALT => self.shlo_l_imm_alt(ins),
            Opcode::SHLO_R_IMM_ALT => self.shlo_r_imm_alt(ins),
            Opcode::SHAR_R_IMM_ALT => self.shar_r_imm_alt(ins),
            Opcode::CMOV_IZ_IMM => self.cmov_iz_imm(ins),
            Opcode::CMOV_NZ_IMM => self.cmov_nz_imm(ins),
            Opcode::BRANCH_EQ => self.branch_eq(ins),
            Opcode::BRANCH_NE => self.branch_ne(ins),
            Opcode::BRANCH_LT_U => self.branch_lt_u(ins),
            Opcode::BRANCH_LT_S => self.branch_lt_s(ins),
            Opcode::BRANCH_GE_U => self.branch_ge_u(ins),
            Opcode::BRANCH_GE_S => self.branch_ge_s(ins),
            Opcode::LOAD_IMM_JUMP_IND => self.load_imm_jump_ind(ins),
            Opcode::ADD => self.add(ins),
            Opcode::SUB => self.sub(ins),
            Opcode::AND => self.and(ins),
            Opcode::XOR => self.xor(ins),
            Opcode::OR => self.or(ins),
            Opcode::MUL => self.mul(ins),
            Opcode::MUL_UPPER_SS => self.mul_upper_s_s(ins),
            Opcode::MUL_UPPER_UU => self.mul_upper_u_u(ins),
            Opcode::MUL_UPPER_SU => self.mul_upper_s_u(ins),
            Opcode::DIV_U => self.div_u(ins),
            Opcode::DIV_S => self.div_s(ins),
            Opcode::REM_U => self.rem_u(ins),
            Opcode::REM_S => self.rem_s(ins),
            Opcode::SET_LT_U => self.set_lt_u(ins),
            Opcode::SET_LT_S => self.set_lt_s(ins),
            Opcode::SHLO_L => self.shlo_l(ins),
            Opcode::SHLO_R => self.shlo_r(ins),
            Opcode::SHAR_R => self.shar_r(ins),
            Opcode::CMOV_IZ => self.cmov_iz(ins),
            Opcode::CMOV_NZ => self.cmov_nz(ins),
        }
    }

    //
    // PVM instruction execution functions
    //

    //
    // Group 0: Helper functions
    //

    /// Determines the next execution step based on a branch condition.
    ///
    /// If the condition is true, attempts to jump to the target address.
    /// The target address must be the beginning of a basic block.
    fn branch(
        &self,
        target: MemAddress,
        condition: bool,
    ) -> Result<(ExitReason, MemAddress), VMError> {
        match (
            condition,
            self.program.basic_block_bitmask.get(target as usize),
        ) {
            (false, _) => Ok((ExitReason::Continue, self.state.pc)),
            (true, Some(true)) => Ok((ExitReason::Continue, target)),
            (true, _) => Ok((ExitReason::Panic, self.state.pc)),
        }
    }

    /// Performs a dynamic jump operation.
    ///
    /// This function handles jumps where the next instruction is dynamically computed.
    /// The jump address is derived from the jump table, with special handling for alignment
    /// and validity checks.
    fn djump(&self, a: usize) -> Result<(ExitReason, MemAddress), VMError> {
        const SPECIAL_HALT_VALUE: usize = (1 << 32) - (1 << 16);

        if a == SPECIAL_HALT_VALUE {
            return Ok((ExitReason::RegularHalt, self.state.pc));
        }

        let jump_table_len = self.program.jump_table.len();

        // Check if 'a' is valid and compute the target
        match (a != 0 && a <= jump_table_len * JUMP_ALIGNMENT && a % JUMP_ALIGNMENT == 0)
            .then(|| self.program.jump_table[(a / JUMP_ALIGNMENT) - 1])
            .filter(|&target| self.program.basic_block_bitmask[target as usize])
        {
            Some(target) => Ok((ExitReason::Continue, target)),
            None => Ok((ExitReason::Panic, self.state.pc)),
        }
    }

    //
    // Group 1: Instructions without Arguments
    //

    /// `panic` with no mutation to the VM state
    ///
    /// Opcode: 0
    fn trap(&self) -> Result<StateChange, VMError> {
        Ok(StateChange {
            exit_reason: ExitReason::Panic,
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Continue program with no mutation to the VM state
    ///
    /// Opcode: 17
    fn fallthrough(&self) -> Result<StateChange, VMError> {
        Ok(StateChange {
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 2: Instructions with Arguments of One Immediate
    //

    /// Invoke host function call
    ///
    /// Opcode: 78
    fn ecalli(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_host_call_type =
            u8::try_from(ins.imm1.unwrap()).map_err(|_| VMError::InvalidImmediateValue)?;

        let exit_reason = HostCallType::from_u8(imm_host_call_type)
            .ok_or(VMError::InvalidHostCallType)
            .map(ExitReason::HostCall)?;

        Ok(StateChange {
            exit_reason,
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 3: Instructions with Arguments of Two Immediates
    //

    /// Store immediate argument value to the memory as `u8` integer type
    ///
    /// Opcode: 62
    fn store_imm_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = vec![(imm_value & 0xFF) as u8]; // mod 2^8

        Ok(StateChange {
            memory_change: (imm_address, value, 1),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store immediate argument value to the memory as `u16` integer type
    ///
    /// Opcode: 79
    fn store_imm_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = ((imm_value & 0xFFFF) as u16).encode_fixed(2)?; // mod 2^16

        Ok(StateChange {
            memory_change: (imm_address, value, 2),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store immediate argument value to the memory as `u32` integer type
    ///
    /// Opcode: 38
    fn store_imm_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = imm_value.encode_fixed(4)?;

        Ok(StateChange {
            memory_change: (imm_address, value, 4),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 4: Instructions with Arguments of One Offset
    //

    /// Jump to the target address with no condition checks
    ///
    /// Opcode: 5
    fn jump(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let (exit_reason, target) = self.branch(ins.imm1.unwrap(), true)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    //
    // Group 5: Instructions with Arguments of One Register & One Immediate
    //

    /// Jump to an address stored in a register plus an immediate offset
    ///
    /// This instruction performs an indirect jump. It adds the value in the specified
    /// register to an immediate value, then jumps to the resulting address.
    ///
    /// Opcode: 19
    fn jump_ind(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let r1_val = self.read_reg(ins.r1.unwrap())?;
        let (exit_reason, target) =
            self.djump(((r1_val as u64 + ins.imm1.unwrap() as u64) % (1 << 32)) as usize)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Load an immediate value into a register
    ///
    /// Opcode: 4
    fn load_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load an unsigned 8-bit value from memory into a register
    ///
    /// Opcode: 60
    fn load_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = self.state.memory.read_byte(imm1)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), val as u32)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load signed 8-bit value from memory into register
    ///
    /// Opcode: 74
    fn load_i8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = self.state.memory.read_byte(imm1)?;
        let signed_val = VMUtils::unsigned_to_signed(1, val as u32).unwrap();
        let unsigned_val = VMUtils::signed_to_unsigned(4, signed_val).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_val)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load unsigned 16-bit value from memory into register
    ///
    /// Opcode: 76
    fn load_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = self.state.memory.read_bytes(imm1, 2)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), u32::decode_fixed(&mut &val[..], 2)?)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load signed 16-bit value from memory into register
    ///
    /// Opcode: 66
    fn load_i16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = self.state.memory.read_bytes(imm1, 2)?;
        let signed_val =
            VMUtils::unsigned_to_signed(2, u32::decode_fixed(&mut &val[..], 2).unwrap()).unwrap();
        let unsigned_val = VMUtils::signed_to_unsigned(4, signed_val).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_val)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load unsigned 32-bit value from memory into register
    ///
    /// Opcode: 10
    fn load_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = self.state.memory.read_bytes(imm1, 4)?;

        Ok(StateChange {
            register_changes: vec![(
                ins.r1.unwrap(),
                u32::decode_fixed(&mut &val[..], 4).unwrap(),
            )],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store register value to the memory as 8-bit unsigned integer
    ///
    /// Opcode: 71
    fn store_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = vec![(ins.r1.unwrap() & 0xFF) as u8];

        Ok(StateChange {
            memory_change: (imm_address, r1_value, 1),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store register value to memory as 16-bit unsigned integer
    ///
    /// Opcode: 69
    fn store_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = (self.read_reg(ins.r1.unwrap())? & 0xFFFF) as u16;

        Ok(StateChange {
            memory_change: (imm_address, r1_value.encode_fixed(2).unwrap(), 2),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store register value to memory as 32-bit unsigned integer
    ///
    /// Opcode: 22
    fn store_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = self.read_reg(ins.r1.unwrap())?;

        Ok(StateChange {
            memory_change: (imm_address, r1_value.encode_fixed(4).unwrap(), 4),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    // TODO: apply `wrapping_add` to other memory index operation as well
    //
    // Group 6: Instructions with Arguments of One Register & Two Immediates
    //

    /// Store immediate 8-bit value to memory indirectly
    ///
    /// Opcode: 26
    fn store_imm_ind_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = vec![(ins.imm2.unwrap() & 0xFF) as u8];

        Ok(StateChange {
            memory_change: (address, value, 1),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store immediate 16-bit value to memory indirectly
    ///
    /// Opcode: 54
    fn store_imm_ind_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = ((ins.imm2.unwrap() & 0xFFFF) as u16).encode_fixed(2)?;

        Ok(StateChange {
            memory_change: (address, value, 2),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store immediate 32-bit value to memory indirectly
    ///
    /// Opcode: 13
    fn store_imm_ind_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = ins.imm2.unwrap().encode_fixed(4)?;

        Ok(StateChange {
            memory_change: (address, value, 4),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 7: Instructions with Arguments of One Register, One Immediate and One Offset
    //

    /// Load immediate value and jump
    ///
    /// Opcode: 6
    fn load_imm_jump(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, true)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if equal to immediate
    ///
    /// Opcode: 7
    fn branch_eq_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? == ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if not equal to immediate
    ///
    /// Opcode: 15
    fn branch_ne_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? != ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than immediate (unsigned)
    ///
    /// Opcode: 44
    fn branch_lt_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? < ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than or equal to immediate (unsigned)
    ///
    /// Opcode: 59
    fn branch_le_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? <= ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than or equal to immediate (unsigned)
    ///
    /// Opcode: 52
    fn branch_ge_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? >= ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than immediate (unsigned)
    ///
    /// Opcode: 50
    fn branch_gt_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let condition = self.read_reg(ins.r1.unwrap())? > ins.imm1.unwrap();
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than immediate (signed)
    ///
    /// Opcode: 32
    fn branch_lt_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let r1_val = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val < imm_val;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than or equal to immediate (signed)
    ///
    /// Opcode: 46
    fn branch_le_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let r1_val = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val <= imm_val;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than or equal to immediate (signed)
    ///
    /// Opcode: 45
    fn branch_ge_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let r1_val = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val >= imm_val;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than immediate (signed)
    ///
    /// Opcode: 53
    fn branch_gt_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let r1_val = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val > imm_val;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    //
    // Group 8: Instructions with Arguments of Two Registers
    //

    /// Move value from one register to another
    ///
    /// Opcode: 82
    fn move_reg(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let value = self.read_reg(ins.r1.unwrap())?;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), value)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// System break (allocate memory)
    ///
    /// This instruction directly mutates the VM memory state unlike other instructions
    ///
    /// Opcode: 87
    fn sbrk(&mut self, ins: &Instruction) -> Result<StateChange, VMError> {
        let requested_size = self.read_reg(ins.r1.unwrap())? as usize;

        // find the first sequence of unavailable memory cells that can satisfy the request
        let alloc_start = self.state.memory.get_break(requested_size)?;

        // try expanding the heap area
        self.state.memory.expand_heap(alloc_start, requested_size)?;

        // returns the start of the newly allocated heap memory
        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), alloc_start)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 9: Instructions with Arguments of Two Registers & One Immediate
    //

    /// Store 8-bit value to memory indirectly
    ///
    /// Opcode: 16
    fn store_ind_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = vec![(self.read_reg(ins.r1.unwrap())? & 0xFF) as u8];

        Ok(StateChange {
            memory_change: (address, value, 1),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store 16-bit value to memory indirectly
    ///
    /// Opcode: 29
    fn store_ind_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = ((self.read_reg(ins.r1.unwrap())? & 0xFFFF) as u16).encode_fixed(2)?;

        Ok(StateChange {
            memory_change: (address, value, 2),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Store 32-bit value to memory indirectly
    ///
    /// Opcode: 3
    fn store_ind_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.read_reg(ins.r1.unwrap())?.encode_fixed(4)?;

        Ok(StateChange {
            memory_change: (address, value, 4),
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load 8-bit unsigned value from memory indirectly
    ///
    /// Opcode: 11
    fn load_ind_u8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.state.memory.read_byte(address)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), value as u32)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load 8-bit signed value from memory indirectly
    ///
    /// Opcode: 21
    fn load_ind_i8(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.state.memory.read_byte(address)?;
        let signed_value = VMUtils::unsigned_to_signed(1, value as u32).unwrap();
        let unsigned_value = VMUtils::signed_to_unsigned(4, signed_value).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_value)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load 16-bit unsigned value from memory indirectly
    ///
    /// Opcode: 37
    fn load_ind_u16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.state.memory.read_bytes(address, 2)?;
        let r_val = u16::decode_fixed(&mut &value[..], 2)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), r_val as u32)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load 16-bit signed value from memory indirectly
    ///
    /// Opcode: 33
    fn load_ind_i16(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.state.memory.read_bytes(address, 2)?;
        let value_decoded = u16::decode_fixed(&mut &value[..], 2)?;
        let signed_value = VMUtils::unsigned_to_signed(2, value_decoded as u32).unwrap();
        let unsigned_value = VMUtils::signed_to_unsigned(4, signed_value).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_value)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Load 32-bit unsigned value from memory indirectly
    ///
    /// Opcode: 1
    fn load_ind_u32(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());
        let value = self.state.memory.read_bytes(address, 4)?;
        let value_decoded = u32::decode_fixed(&mut &value[..], 4)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), value_decoded)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Add immediate to register
    ///
    /// Opcode: 2
    fn add_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm1.unwrap());

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise AND with immediate
    ///
    /// Opcode: 18
    fn and_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r2.unwrap())? & ins.imm1.unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise XOR with immediate
    ///
    /// Opcode: 31
    fn xor_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r2.unwrap())? ^ ins.imm1.unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise OR with immediate
    ///
    /// Opcode: 49
    fn or_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r2.unwrap())? | ins.imm1.unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply with immediate
    ///
    /// Opcode: 35
    fn mul_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_mul(ins.imm1.unwrap());

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply upper (signed * signed) with immediate
    ///
    /// Opcode: 65
    fn mul_upper_s_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap() as i64;
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap() as i64;
        let result = ((a * b) >> 32) as i32; // implicitly conducts floor operation
        let unsigned_result = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply upper (unsigned * unsigned) with immediate
    ///
    /// Opcode: 63
    fn mul_upper_u_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r2.unwrap())? as u64;
        let b = ins.imm1.unwrap() as u64;
        let result = ((a * b) >> 32) as u32; // implicitly conducts floor operation

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if less than immediate (unsigned)
    ///
    /// Opcode: 27
    fn set_lt_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r2.unwrap())?;
        let b = ins.imm1.unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if less than immediate (signed)
    ///
    /// Opcode: 56
    fn set_lt_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift left logical with immediate
    ///
    /// Opcode: 9
    fn shlo_l_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let result = self.read_reg(ins.r2.unwrap())? << shift;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right logical with immediate
    ///
    /// Opcode: 14
    fn shlo_r_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let result = self.read_reg(ins.r2.unwrap())? >> shift;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right arithmetic with immediate
    ///
    /// Opcode: 25
    fn shar_r_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let value = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let result = value >> shift;
        let unsigned_result = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), unsigned_result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Negate and add immediate
    ///
    /// Opcode: 40
    fn neg_add_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = ins
            .imm1
            .unwrap()
            .wrapping_sub(self.read_reg(ins.r2.unwrap())?);

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if greater than immediate (unsigned)
    ///
    /// Opcode: 39
    fn set_gt_u_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r2.unwrap())?;
        let b = ins.imm1.unwrap();
        let result = if a > b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if greater than immediate (signed)
    ///
    /// Opcode: 61
    fn set_gt_s_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = if a > b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift left logical immediate (alternative)
    ///
    /// Opcode: 75
    fn shlo_l_imm_alt(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = ins.imm1.unwrap() << shift;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right logical immediate (alternative)
    ///
    /// Opcode: 72
    fn shlo_r_imm_alt(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = ins.imm1.unwrap() >> shift;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right arithmetic immediate (alternative)
    ///
    /// Opcode: 80
    fn shar_r_imm_alt(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let value = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = value >> shift;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result_unsigned)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Conditional move if zero with immediate
    ///
    /// Opcode: 85
    fn cmov_iz_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = if self.read_reg(ins.r2.unwrap())? == 0 {
            ins.imm1.unwrap()
        } else {
            self.read_reg(ins.r1.unwrap())?
        };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Conditional move if not zero with immediate
    ///
    /// Opcode: 86
    fn cmov_nz_imm(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = if self.read_reg(ins.r2.unwrap())? != 0 {
            ins.imm1.unwrap()
        } else {
            self.read_reg(ins.r1.unwrap())?
        };

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    //
    // Group 10: Instructions with Arguments of Two Registers & One Offset
    //

    /// Branch if equal
    ///
    /// Opcode: 24
    fn branch_eq(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())?;
        let b = self.read_reg(ins.r2.unwrap())?;
        let condition = a == b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if not equal
    ///
    /// Opcode: 30
    fn branch_ne(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())?;
        let b = self.read_reg(ins.r2.unwrap())?;
        let condition = a != b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than (unsigned)
    ///
    /// Opcode: 47
    fn branch_lt_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())?;
        let b = self.read_reg(ins.r2.unwrap())?;
        let condition = a < b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if less than (signed)
    ///
    /// Opcode: 48
    fn branch_lt_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let condition = a < b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than or equal (unsigned)
    ///
    /// Opcode: 41
    fn branch_ge_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())?;
        let b = self.read_reg(ins.r2.unwrap())?;
        let condition = a >= b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    /// Branch if greater than or equal (signed)
    ///
    /// Opcode: 43
    fn branch_ge_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let condition = a >= b;
        let (exit_reason, target) = self.branch(ins.offset.unwrap() as u32, condition)?;

        Ok(StateChange {
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    //
    // Group 11: Instructions with Arguments of Two Registers & Two Immediates
    //

    /// Load immediate and jump indirect
    ///
    /// Opcode: 42
    fn load_imm_jump_ind(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let jump_address = self
            .read_reg(ins.r2.unwrap())?
            .wrapping_add(ins.imm2.unwrap());
        let (exit_reason, target) = self.djump(jump_address as usize)?;

        Ok(StateChange {
            register_changes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
            pc_change: Some(target),
            exit_reason,
            ..Default::default()
        })
    }

    //
    // Group 12: Instructions with Arguments of Three Registers
    //

    /// Add two registers
    ///
    /// Opcode: 8
    fn add(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_add(self.read_reg(ins.r2.unwrap())?);

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Subtract two registers
    ///
    /// Opcode: 20
    fn sub(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_sub(self.read_reg(ins.r2.unwrap())?);

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise AND of two registers
    ///
    /// Opcode: 23
    fn and(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r1.unwrap())? & self.read_reg(ins.r2.unwrap())?;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise XOR of two registers
    ///
    /// Opcode: 28
    fn xor(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r1.unwrap())? ^ self.read_reg(ins.r2.unwrap())?;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Bitwise OR of two registers
    ///
    /// Opcode: 12
    fn or(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self.read_reg(ins.r1.unwrap())? | self.read_reg(ins.r2.unwrap())?;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply two registers
    ///
    /// Opcode: 34
    fn mul(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = self
            .read_reg(ins.r1.unwrap())?
            .wrapping_mul(self.read_reg(ins.r2.unwrap())?);

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply upper (signed * signed)
    ///
    /// Opcode: 67
    fn mul_upper_s_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap() as i64;
        let b = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap() as i64;
        let result = ((a * b) >> 32) as i32;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result_unsigned)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply upper (unsigned * unsigned)
    ///
    /// Opcode: 57
    fn mul_upper_u_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())? as u64;
        let b = self.read_reg(ins.r2.unwrap())? as u64;
        let result = ((a * b) >> 32) as u32;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Multiply upper (signed * unsigned)
    ///
    /// Opcode: 81
    fn mul_upper_s_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap() as i64;
        let b = self.read_reg(ins.r2.unwrap())? as u64;
        let result = ((a * b as i64) >> 32) as i32;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result_unsigned)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Divide unsigned
    ///
    /// Opcode: 68
    fn div_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let dividend = self.read_reg(ins.r1.unwrap())?;
        let divisor = self.read_reg(ins.r2.unwrap())?;
        let result = if divisor == 0 {
            u32::MAX
        } else {
            dividend.wrapping_div(divisor)
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Divide signed
    ///
    /// Opcode: 64
    fn div_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let dividend = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let divisor = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let result = if divisor == 0 {
            u32::MAX
        } else if dividend == i32::MIN && divisor == -1 {
            self.read_reg(ins.r1.unwrap())?
        } else {
            VMUtils::signed_to_unsigned(4, dividend.wrapping_div(divisor)).unwrap()
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Remainder unsigned
    ///
    /// Opcode: 73
    fn rem_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let dividend = self.read_reg(ins.r1.unwrap())?;
        let divisor = self.read_reg(ins.r2.unwrap())?;
        let result = if divisor == 0 {
            dividend
        } else {
            dividend % divisor
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Remainder signed
    ///
    /// Opcode: 70
    fn rem_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let dividend = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let divisor = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let result = if divisor == 0 {
            self.read_reg(ins.r1.unwrap())?
        } else if dividend == i32::MIN && divisor == -1 {
            0
        } else {
            VMUtils::signed_to_unsigned(4, dividend % divisor).unwrap()
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if less than (unsigned)
    ///
    /// Opcode: 36
    fn set_lt_u(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = self.read_reg(ins.r1.unwrap())?;
        let b = self.read_reg(ins.r2.unwrap())?;
        let result = if a < b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Set if less than (signed)
    ///
    /// Opcode: 58
    fn set_lt_s(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let a = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r2.unwrap())?).unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift left logical
    ///
    /// Opcode: 55
    fn shlo_l(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = self.read_reg(ins.r1.unwrap())? << shift;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right logical
    ///
    /// Opcode: 51
    fn shlo_r(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = self.read_reg(ins.r1.unwrap())? >> shift;

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Shift right arithmetic
    ///
    /// Opcode: 77
    fn shar_r(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let shift = self.read_reg(ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let value = VMUtils::unsigned_to_signed(4, self.read_reg(ins.r1.unwrap())?).unwrap();
        let result = value >> shift;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result_unsigned)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Conditional move if zero
    ///
    /// Opcode: 83
    fn cmov_iz(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = if self.read_reg(ins.r2.unwrap())? == 0 {
            self.read_reg(ins.r1.unwrap())?
        } else {
            self.read_reg(ins.rd.unwrap())?
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }

    /// Conditional move if not zero
    ///
    /// Opcode: 84
    fn cmov_nz(&self, ins: &Instruction) -> Result<StateChange, VMError> {
        let result = if self.read_reg(ins.r2.unwrap())? != 0 {
            self.read_reg(ins.r1.unwrap())?
        } else {
            self.read_reg(ins.rd.unwrap())?
        };

        Ok(StateChange {
            register_changes: vec![(ins.rd.unwrap(), result)],
            pc_change: Some(self.next_pc()),
            ..Default::default()
        })
    }
}

impl Memory {
    fn new(size: usize, page_size: usize) -> Self {
        let cells = vec![MemoryCell::default(); size];
        Memory {
            cells,
            page_size,
            heap_start: 0,
        }
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
    fn read_byte(&self, address: MemAddress) -> Result<u8, VMError> {
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

    /// Read a specified number of bytes from memory starting at the given address
    pub fn read_bytes(&self, address: MemAddress, length: usize) -> Result<Octets, VMError> {
        (0..length)
            .map(|i| self.read_byte(address + i as MemAddress))
            .collect()
    }

    /// Write a slice of bytes to memory starting at the given address
    pub fn write_bytes(&mut self, address: MemAddress, bytes: &[u8]) -> Result<(), VMError> {
        for (i, &byte) in bytes.iter().enumerate() {
            self.write_u8(address + i as MemAddress, byte)?;
        }
        Ok(())
    }

    /// Get the break address (end of the heap) of current memory layout
    fn get_break(&self, requested_size: usize) -> Result<MemAddress, VMError> {
        let heap_start = self.heap_start;

        let mut current_start = heap_start;
        let mut consecutive_unavailable = 0;

        for (i, cell) in self.cells[heap_start as usize..].iter().enumerate() {
            if cell.status == CellStatus::Unavailable {
                consecutive_unavailable += 1;
                if consecutive_unavailable == requested_size {
                    return Ok(current_start);
                }
            } else {
                current_start = heap_start + i as MemAddress + 1;
                consecutive_unavailable = 0;
            }
        }
        Err(VMError::OutOfMemory)
    }

    /// Expand the heap (read-write) area for the `sbrk` instruction
    fn expand_heap(&mut self, start: MemAddress, size: usize) -> Result<(), VMError> {
        let end = start
            .checked_add(size as MemAddress)
            .ok_or(VMError::OutOfMemory)?;

        if end as usize > self.cells.len() {
            return Err(VMError::OutOfMemory);
        }

        // mark the new cells (expanding heap area) as writable
        for cell in &mut self.cells[start as usize..end as usize] {
            cell.status = CellStatus::Writable;
            cell.access = AccessType::ReadWrite;
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
        r1: Option<usize>,
        r2: Option<usize>,
        rd: Option<usize>,
        imm1: Option<u32>,
        imm2: Option<u32>,
        offset: Option<i32>,
    ) -> Result<Self, VMError> {
        // Validate register indices
        for &reg in [rd, r1, r2].iter().flatten() {
            if reg > (REGISTERS_COUNT - 1) {
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
            + VMUtils::q(self.read_only_len as usize)
            + VMUtils::q(
                self.read_write_len as usize + (self.extra_heap_pages as usize) * PAGE_SIZE,
            )
            + VMUtils::q(self.stack_size as usize)
            + INPUT_SIZE;
        condition_value <= STANDARD_PROGRAM_SIZE_LIMIT
    }
}

impl Default for StateChange {
    fn default() -> Self {
        Self {
            register_changes: vec![],
            memory_change: (0, vec![], 0),
            pc_change: None,
            gas_change: 0,
            exit_reason: ExitReason::Continue,
        }
    }
}

impl VMUtils {
    //
    // Program initialization util functions
    //

    fn p(x: usize) -> usize {
        // P(x) = Z_P * ceil(x / Z_P)
        PAGE_SIZE * ((x + PAGE_SIZE - 1) / PAGE_SIZE)
    }

    fn q(x: usize) -> usize {
        // Q(x) = Z_Q * ceil(x / Z_Q)
        SEGMENT_SIZE * ((x + SEGMENT_SIZE - 1) / SEGMENT_SIZE)
    }

    //
    // Instruction arguments processing functions
    //

    /// Converts an unsigned integer to a signed integer of the same bit width.
    /// Represents `Z_n` in the GP
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `a`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// The signed equivalent of the input, or None if `n` is 0 or greater than 4.
    pub fn unsigned_to_signed(n: u32, a: u32) -> Option<i32> {
        match n {
            1..=4 => {
                let max_positive = 1u32 << (8 * n - 1);
                if a < max_positive {
                    Some(a as i32)
                } else {
                    Some((a as i32) - (1i32 << (8 * n)))
                }
            }
            _ => None,
        }
    }

    /// Converts a signed integer to an unsigned integer of the same bit width.
    /// Represents `{Z_n}^-1` in the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `a`: The signed integer to convert.
    ///
    /// # Returns
    ///
    /// The unsigned equivalent of the input, or None if `n` is 0 or greater than 4.
    pub fn signed_to_unsigned(n: u32, a: i32) -> Option<u32> {
        match n {
            1..=4 => {
                let modulus = 1u32 << (8 * n);
                Some(((modulus as i64 + a as i64) % modulus as i64) as u32)
            }
            _ => None,
        }
    }

    /// Converts an unsigned integer to its binary representation.
    /// Represents `B_n` in the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `x`: The unsigned integer to convert.
    ///
    /// # Returns
    ///
    /// A vector of booleans representing the binary form of the input,
    /// or None if `n` is 0 or greater than 4.
    pub fn int_to_bitvec(n: u32, x: u32) -> Option<BitVec> {
        match n {
            1..=4 => {
                let mut result = BitVec::from_elem((8 * n) as usize, false);
                for i in 0..(8 * n) {
                    result.set(i as usize, (x >> i) & 1 == 1);
                }
                Some(result)
            }
            _ => None,
        }
    }

    /// Converts a binary representation back to an unsigned integer.
    /// Represents `{B_n}^-1` in the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the integer.
    /// * `x`: A vector of booleans representing the binary form.
    ///
    /// # Returns
    ///
    /// The unsigned integer represented by the input binary form,
    /// or None if `n` is 0 or greater than 4, or if the input vector's length doesn't match 8*n.
    pub fn bitvec_to_int(n: u32, x: &BitVec) -> Option<u32> {
        if n == 0 || n > 4 || x.len() != (8 * n) as usize {
            return None;
        }

        Some(
            x.iter()
                .enumerate()
                .fold(0, |acc, (i, bit)| acc | ((bit as u32) << i)),
        )
    }

    /// Performs signed extension on an unsigned integer.
    /// Represents `X_n` in the GP
    ///
    /// # Arguments
    ///
    /// * `n`: The number of octets (8-bit units) in the input integer.
    /// * `x`: The unsigned integer to extend.
    ///
    /// # Returns
    ///
    /// The sign-extended 32-bit unsigned integer, or None if `n` is 0 or greater than 4.
    pub fn signed_extend(n: u32, x: u32) -> Option<u32> {
        match n {
            1..=4 => {
                let msb = x >> (8 * n - 1);
                let extension = msb * (u32::MAX - (1 << (8 * n)) + 1);
                Some(x + extension)
            }
            _ => None,
        }
    }
}
