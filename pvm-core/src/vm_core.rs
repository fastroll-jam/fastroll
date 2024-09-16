use crate::{
    constants::REGISTERS_COUNT,
    instructions::InstructionSet as IS,
    memory::{MemAddress, Memory},
    opcode::Opcode,
    program_decoder::{Instruction, ProgramDecoder},
    register::Register,
    types::{ExitReason, VMError},
};
use bit_vec::BitVec;
use jam_common::{Octets, UnsignedGas};

/// Mutable VM state
#[derive(Clone)]
pub struct VMState {
    pub registers: [Register; REGISTERS_COUNT], // omega
    pub memory: Memory,                         // mu
    pub pc: MemAddress,                         // iota
    pub gas_counter: UnsignedGas,               // xi
}

/// Immutable program components
#[derive(Default)]
pub struct Program {
    pub program_code: Octets, // p (`c` of the Initialization Decoder Function `Y`)
    pub instructions: Octets, // c; serialized
    pub jump_table: Vec<MemAddress>, // j
    pub opcode_bitmask: BitVec, // k
    pub basic_block_bitmask: BitVec, // bitmask to detect opcode addresses that begin basic blocks
}

pub struct StateChange {
    pub register_writes: Vec<(usize, u32)>,
    pub memory_write: (MemAddress, u32, Octets), // (start_address, data_len, data)
    pub new_pc: Option<MemAddress>,
    pub gas_usage: UnsignedGas,
}

impl Default for StateChange {
    fn default() -> Self {
        Self {
            register_writes: vec![],
            memory_write: (0, 0, vec![]),
            new_pc: None,
            gas_usage: 0,
        }
    }
}

pub struct SingleInvocationResult {
    pub exit_reason: ExitReason,
    pub state_change: StateChange,
}

pub struct PVMCore;

impl PVMCore {
    //
    // PVM helper functions
    //

    /// Read a `u32` value stored in a register of the given index
    pub fn read_reg(vm_state: &VMState, index: usize) -> Result<u32, VMError> {
        Ok(vm_state.registers[index].value)
    }

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

        skip_distance.min(max_skip)
    }

    /// Get the next pc value from the current VM state and the skip function
    /// for normal instruction execution completion
    pub fn next_pc(vm_state: &VMState, program: &Program) -> MemAddress {
        1 + Self::skip(vm_state.pc, &program.instructions, &program.opcode_bitmask) as MemAddress
    }

    /// Set `basic_blocks` array of the VM immutable state utilizing instructions blob and opcode bitmask
    fn set_basic_block_bitmask(program: &mut Program) -> Result<(), VMError> {
        let bitmask_len = program.opcode_bitmask.len();
        let mut basic_block_bitmask = BitVec::from_elem(bitmask_len, false);

        // MemAddress 0 always starts a basic block
        basic_block_bitmask.set(0, true);

        for n in 0..bitmask_len {
            if program.opcode_bitmask.get(n).unwrap() {
                if let Some(op) = Opcode::from_u8(n as u8) {
                    if op.is_termination_opcode() {
                        let basic_block_start_address = n
                            + 1
                            + Self::skip(
                                n as MemAddress,
                                &program.instructions,
                                &program.opcode_bitmask,
                            );
                        basic_block_bitmask.set(basic_block_start_address, true);
                    }
                }
            }
        }

        program.basic_block_bitmask = basic_block_bitmask;
        Ok(())
    }

    /// Mutate the VM states from the change set produced by single-step instruction execution functions
    fn apply_state_change(vm_state: &mut VMState, change: StateChange) -> Result<(), VMError> {
        // Apply register changes
        for (reg_index, new_value) in change.register_writes {
            if reg_index < REGISTERS_COUNT {
                vm_state.registers[reg_index] = Register { value: new_value };
            } else {
                eprintln!(
                    "Warning: Attempted to change invalid register index: {}",
                    reg_index
                );
            }
        }

        // Apply memory change
        let (start_address, data_len, data) = change.memory_write;
        if data_len as usize <= data.len() {
            for (offset, &byte) in data.iter().take(data_len as usize).enumerate() {
                if let Err(e) = vm_state
                    .memory
                    .write_byte(start_address.wrapping_add(offset as u32), byte)
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
        if let Some(new_pc) = change.new_pc {
            vm_state.pc = new_pc;
        }

        // Apply gas change
        vm_state.gas_counter -= change.gas_usage;
        // TODO: add a separate gas check logic outside this function
        // if self.state.gas_counter >= change.gas_usage {
        //     self.state.gas_counter -= change.gas_usage;
        // } else {
        //     return ExitReason::OutOfGas;
        // }

        Ok(())
    }

    /// Recursively call single-step invocation functions following the instruction sequence
    /// Mutating the VM states
    ///
    /// Represents `Psi` of the GP
    pub fn general_invocation(
        vm_state: &mut VMState,
        program: &mut Program,
    ) -> Result<ExitReason, VMError> {
        // Decode program code into (instructions blob, opcode bitmask, dynamic jump table)
        let (instructions, opcode_bitmask, jump_table) =
            ProgramDecoder::decode_program_code(&program.program_code)?;

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_bitmask
        program.instructions = instructions;
        program.opcode_bitmask = opcode_bitmask;
        program.jump_table = jump_table;
        Self::set_basic_block_bitmask(program)?;

        loop {
            let skip_distance =
                Self::skip(vm_state.pc, &program.instructions, &program.opcode_bitmask);

            let current_pc = vm_state.pc;
            let address = current_pc as usize;
            let next_address = address + 1 + skip_distance;

            // Instruction blob length is not greater than 16
            let instruction_blob = {
                let full_slice = &program.instructions[address..next_address];
                if full_slice.len() > 16 {
                    &full_slice[..16]
                } else {
                    full_slice
                }
            };

            // TODO: define instruction_blob with endless zeroes padding
            let ins =
                ProgramDecoder::decode_instruction(&instruction_blob, current_pc, skip_distance)?;

            let single_invocation_result = Self::single_step_invocation(vm_state, program, &ins)?;

            Self::apply_state_change(vm_state, single_invocation_result.state_change)?;
            match single_invocation_result.exit_reason {
                ExitReason::Continue => continue,
                ExitReason::OutOfGas => return Ok(ExitReason::OutOfGas),
                other => return Ok(other),
            }
        }
    }

    /// Single-step PVM state transition function
    /// Refers to the VM states e.g. `pc`, `memory`, `instructions` from the `&self` state
    /// and returns the VM state change as an output
    ///
    /// Instruction `SBRK` is the only instruction that directly mutates the VM state, for a new heap allocation
    ///
    /// Represents `Psi_1` of the GP
    fn single_step_invocation(
        vm_state: &mut VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, VMError> {
        match ins.op {
            Opcode::TRAP => IS::trap(vm_state, program),
            Opcode::FALLTHROUGH => IS::fallthrough(vm_state, program),
            Opcode::ECALLI => IS::ecalli(vm_state, program, ins),
            Opcode::STORE_IMM_U8 => IS::store_imm_u8(vm_state, program, ins),
            Opcode::STORE_IMM_U16 => IS::store_imm_u16(vm_state, program, ins),
            Opcode::STORE_IMM_U32 => IS::store_imm_u32(vm_state, program, ins),
            Opcode::JUMP => IS::jump(vm_state, program, ins),
            Opcode::JUMP_IND => IS::jump_ind(vm_state, program, ins),
            Opcode::LOAD_IMM => IS::load_imm(vm_state, program, ins),
            Opcode::LOAD_U8 => IS::load_u8(vm_state, program, ins),
            Opcode::LOAD_I8 => IS::load_i8(vm_state, program, ins),
            Opcode::LOAD_U16 => IS::load_u16(vm_state, program, ins),
            Opcode::LOAD_I16 => IS::load_i16(vm_state, program, ins),
            Opcode::LOAD_U32 => IS::load_u32(vm_state, program, ins),
            Opcode::STORE_U8 => IS::store_u8(vm_state, program, ins),
            Opcode::STORE_U16 => IS::store_u16(vm_state, program, ins),
            Opcode::STORE_U32 => IS::store_u32(vm_state, program, ins),
            Opcode::STORE_IMM_IND_U8 => IS::store_imm_ind_u8(vm_state, program, ins),
            Opcode::STORE_IMM_IND_U16 => IS::store_imm_ind_u16(vm_state, program, ins),
            Opcode::STORE_IMM_IND_U32 => IS::store_imm_ind_u32(vm_state, program, ins),
            Opcode::LOAD_IMM_JUMP => IS::load_imm_jump(vm_state, program, ins),
            Opcode::BRANCH_EQ_IMM => IS::branch_eq_imm(vm_state, program, ins),
            Opcode::BRANCH_NE_IMM => IS::branch_ne_imm(vm_state, program, ins),
            Opcode::BRANCH_LT_U_IMM => IS::branch_lt_u_imm(vm_state, program, ins),
            Opcode::BRANCH_LE_U_IMM => IS::branch_le_u_imm(vm_state, program, ins),
            Opcode::BRANCH_GE_U_IMM => IS::branch_ge_u_imm(vm_state, program, ins),
            Opcode::BRANCH_GT_U_IMM => IS::branch_gt_u_imm(vm_state, program, ins),
            Opcode::BRANCH_LT_S_IMM => IS::branch_lt_s_imm(vm_state, program, ins),
            Opcode::BRANCH_LE_S_IMM => IS::branch_le_s_imm(vm_state, program, ins),
            Opcode::BRANCH_GE_S_IMM => IS::branch_ge_s_imm(vm_state, program, ins),
            Opcode::BRANCH_GT_S_IMM => IS::branch_gt_s_imm(vm_state, program, ins),
            Opcode::MOVE_REG => IS::move_reg(vm_state, program, ins),
            Opcode::SBRK => IS::sbrk(vm_state, program, ins),
            Opcode::STORE_IND_U8 => IS::store_ind_u8(vm_state, program, ins),
            Opcode::STORE_IND_U16 => IS::store_ind_u16(vm_state, program, ins),
            Opcode::STORE_IND_U32 => IS::store_ind_u32(vm_state, program, ins),
            Opcode::LOAD_IND_U8 => IS::load_ind_u8(vm_state, program, ins),
            Opcode::LOAD_IND_I8 => IS::load_ind_i8(vm_state, program, ins),
            Opcode::LOAD_IND_U16 => IS::load_ind_u16(vm_state, program, ins),
            Opcode::LOAD_IND_I16 => IS::load_ind_i16(vm_state, program, ins),
            Opcode::LOAD_IND_U32 => IS::load_ind_u32(vm_state, program, ins),
            Opcode::ADD_IMM => IS::add_imm(vm_state, program, ins),
            Opcode::AND_IMM => IS::and_imm(vm_state, program, ins),
            Opcode::XOR_IMM => IS::xor_imm(vm_state, program, ins),
            Opcode::OR_IMM => IS::or_imm(vm_state, program, ins),
            Opcode::MUL_IMM => IS::mul_imm(vm_state, program, ins),
            Opcode::MUL_UPPER_SS_IMM => IS::mul_upper_s_s_imm(vm_state, program, ins),
            Opcode::MUL_UPPER_UU_IMM => IS::mul_upper_u_u_imm(vm_state, program, ins),
            Opcode::SET_LT_U_IMM => IS::set_lt_u_imm(vm_state, program, ins),
            Opcode::SET_LT_S_IMM => IS::set_lt_s_imm(vm_state, program, ins),
            Opcode::SHLO_L_IMM => IS::shlo_l_imm(vm_state, program, ins),
            Opcode::SHLO_R_IMM => IS::shlo_r_imm(vm_state, program, ins),
            Opcode::SHAR_R_IMM => IS::shar_r_imm(vm_state, program, ins),
            Opcode::NEG_ADD_IMM => IS::neg_add_imm(vm_state, program, ins),
            Opcode::SET_GT_U_IMM => IS::set_gt_u_imm(vm_state, program, ins),
            Opcode::SET_GT_S_IMM => IS::set_gt_s_imm(vm_state, program, ins),
            Opcode::SHLO_L_IMM_ALT => IS::shlo_l_imm_alt(vm_state, program, ins),
            Opcode::SHLO_R_IMM_ALT => IS::shlo_r_imm_alt(vm_state, program, ins),
            Opcode::SHAR_R_IMM_ALT => IS::shar_r_imm_alt(vm_state, program, ins),
            Opcode::CMOV_IZ_IMM => IS::cmov_iz_imm(vm_state, program, ins),
            Opcode::CMOV_NZ_IMM => IS::cmov_nz_imm(vm_state, program, ins),
            Opcode::BRANCH_EQ => IS::branch_eq(vm_state, program, ins),
            Opcode::BRANCH_NE => IS::branch_ne(vm_state, program, ins),
            Opcode::BRANCH_LT_U => IS::branch_lt_u(vm_state, program, ins),
            Opcode::BRANCH_LT_S => IS::branch_lt_s(vm_state, program, ins),
            Opcode::BRANCH_GE_U => IS::branch_ge_u(vm_state, program, ins),
            Opcode::BRANCH_GE_S => IS::branch_ge_s(vm_state, program, ins),
            Opcode::LOAD_IMM_JUMP_IND => IS::load_imm_jump_ind(vm_state, program, ins),
            Opcode::ADD => IS::add(vm_state, program, ins),
            Opcode::SUB => IS::sub(vm_state, program, ins),
            Opcode::AND => IS::and(vm_state, program, ins),
            Opcode::XOR => IS::xor(vm_state, program, ins),
            Opcode::OR => IS::or(vm_state, program, ins),
            Opcode::MUL => IS::mul(vm_state, program, ins),
            Opcode::MUL_UPPER_SS => IS::mul_upper_s_s(vm_state, program, ins),
            Opcode::MUL_UPPER_UU => IS::mul_upper_u_u(vm_state, program, ins),
            Opcode::MUL_UPPER_SU => IS::mul_upper_s_u(vm_state, program, ins),
            Opcode::DIV_U => IS::div_u(vm_state, program, ins),
            Opcode::DIV_S => IS::div_s(vm_state, program, ins),
            Opcode::REM_U => IS::rem_u(vm_state, program, ins),
            Opcode::REM_S => IS::rem_s(vm_state, program, ins),
            Opcode::SET_LT_U => IS::set_lt_u(vm_state, program, ins),
            Opcode::SET_LT_S => IS::set_lt_s(vm_state, program, ins),
            Opcode::SHLO_L => IS::shlo_l(vm_state, program, ins),
            Opcode::SHLO_R => IS::shlo_r(vm_state, program, ins),
            Opcode::SHAR_R => IS::shar_r(vm_state, program, ins),
            Opcode::CMOV_IZ => IS::cmov_iz(vm_state, program, ins),
            Opcode::CMOV_NZ => IS::cmov_nz(vm_state, program, ins),
        }
    }
}
