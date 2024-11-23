use crate::{
    constants::REGISTERS_COUNT,
    program::{
        instructions::InstructionSet as IS,
        opcode::Opcode,
        program_decoder::{Instruction, ProgramDecoder, ProgramState},
    },
    state::{
        memory::{MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, RegValue},
        error::{
            PVMError,
            VMCoreError::{InvalidRegIndex, InvalidRegValue, MemoryStateChangeDataLengthMismatch},
        },
    },
};
use bit_vec::BitVec;
use rjam_common::UnsignedGas;

pub struct SingleInvocationResult {
    pub exit_reason: ExitReason,
    pub state_change: StateChange,
}

/// Mutable VM state
#[derive(Clone, Default)]
pub struct VMState {
    pub registers: [Register; REGISTERS_COUNT], // omega
    pub memory: Memory,                         // mu
    pub pc: RegValue,                           // iota
    pub gas_counter: UnsignedGas,               // xi
}

impl VMState {
    pub fn pc(&self) -> RegValue {
        self.pc
    }

    pub fn pc_as_mem_address(&self) -> Result<MemAddress, PVMError> {
        MemAddress::try_from(self.pc).map_err(|_| PVMError::VMCoreError(InvalidRegValue))
    }
}

/// VM mutable state change set
#[derive(Default)]
pub struct StateChange {
    pub register_writes: Vec<(usize, RegValue)>,
    pub memory_write: (MemAddress, u32, Vec<u8>), // (start_address, data_len, data)
    pub new_pc: Option<RegValue>,
    pub gas_usage: UnsignedGas,
}

pub struct PVMCore;

impl PVMCore {
    //
    // PVM util functions
    //

    /// Read a `u64` value stored in a register of the given index
    pub fn read_reg(vm_state: &VMState, index: usize) -> Result<RegValue, PVMError> {
        Ok(vm_state.registers[index].value())
    }

    pub fn read_reg_as_mem_address(
        vm_state: &VMState,
        index: usize,
    ) -> Result<MemAddress, PVMError> {
        vm_state.registers[index].as_mem_address()
    }

    pub fn read_reg_as_reg_index(vm_state: &VMState, index: usize) -> Result<usize, PVMError> {
        vm_state.registers[index].as_reg_index()
    }

    /// Skip function that calculates skip distance to the next instruction from the instruction
    /// sequence and the opcode bitmask
    fn skip(curr_opcode_index: usize, opcode_bitmask: &BitVec) -> usize {
        const MAX_SKIP: usize = 24;

        for skip_distance in 1..=MAX_SKIP {
            if opcode_bitmask
                .get(curr_opcode_index + 1 + skip_distance)
                .unwrap_or(true)
            {
                return skip_distance;
            }
        }

        MAX_SKIP // Note: this case implies malformed program.
    }

    /// Get the next pc value from the current VM state and the skip function
    /// for normal instruction execution completion
    pub fn next_pc(vm_state: &VMState, program_state: &ProgramState) -> RegValue {
        1 + Self::skip(vm_state.pc as usize, &program_state.opcode_bitmask) as RegValue
    }

    /// Collects opcode indices that indicate beginning of basic blocks and sets the
    /// `basic_block_start_indices` of the `ProgramState`.
    fn set_basic_block_start_indices(program: &mut ProgramState) -> Result<(), PVMError> {
        program.basic_block_start_indices.insert(0);
        let instructions_len = program.instructions.len();

        for n in 1..instructions_len {
            if let Some(true) = program.opcode_bitmask.get(n) {
                if let Some(&op_val) = program.instructions.get(n) {
                    let op = Opcode::from_u8(op_val)?;
                    if op.is_termination_opcode() {
                        let next_op_index = n + 1 + Self::skip(n, &program.opcode_bitmask);
                        program.basic_block_start_indices.insert(next_op_index);
                    }
                }
            }
        }

        Ok(())
    }

    /// Decodes program code blob and load into program state components: instructions, an opcode bitmask,
    /// a dynamic jump table and a basic block bitmask.
    fn set_program_state(
        program_code: &[u8],
        program_state: &mut ProgramState,
    ) -> Result<(), PVMError> {
        // Decode program code into (instructions blob, opcode bitmask, dynamic jump table)
        let (instructions, opcode_bitmask, jump_table) =
            ProgramDecoder::decode_program_code(program_code)?;

        // Initialize immutable PVM states: instructions, opcode_bitmask, jump_table and basic_block_bitmask
        program_state.instructions = instructions;
        program_state.opcode_bitmask = opcode_bitmask;
        program_state.jump_table = jump_table;
        Self::set_basic_block_start_indices(program_state)?;
        Ok(())
    }

    /// Mutate the VM states from the change set produced by single-step instruction execution functions
    fn apply_state_change(vm_state: &mut VMState, change: StateChange) -> Result<(), PVMError> {
        // Apply register changes
        for (reg_index, new_value) in change.register_writes {
            if reg_index >= REGISTERS_COUNT {
                return Err(PVMError::VMCoreError(InvalidRegIndex(reg_index)));
            }
            vm_state.registers[reg_index] = Register { value: new_value };
        }

        // Apply memory change
        // FIXME: data_len arg is redundant
        let (start_address, data_len, data) = change.memory_write;
        if data_len as usize > data.len() {
            return Err(PVMError::VMCoreError(MemoryStateChangeDataLengthMismatch));
        }

        vm_state.memory.write_bytes(start_address, &data)?;

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

    //
    // Common PVM invocation functions
    //

    /// General PVM invocation function.
    ///
    /// This function recursively calls single-step invocation functions following the instruction
    /// sequence mutating the VM states.
    ///
    /// # Input Program
    /// This function utilizes the program component of the `PVM` state. The program is decoded
    /// into instructions sequence, an opcode bitmask, and a dynamic jump table, which are then passed
    /// as arguments to the `single_step_invocation` function.
    ///
    /// Represents `Ψ` of the GP.
    pub fn general_invocation(
        vm_state: &mut VMState,
        program_state: &mut ProgramState, // no data loaded at this point
        program_code: &[u8],
    ) -> Result<ExitReason, PVMError> {
        // Decode program blob and set the program state to be referenced in each single-step invocation function.
        Self::set_program_state(program_code, program_state)?;

        loop {
            let skip_distance = Self::skip(vm_state.pc as usize, &program_state.opcode_bitmask);

            let current_pc = vm_state.pc;
            let address = current_pc as usize;
            let next_address = address + 1 + skip_distance;

            // Instruction blob length is not greater than 16
            let instruction_blob = {
                let full_slice = &program_state.instructions[address..next_address];
                if full_slice.len() > 16 {
                    &full_slice[..16]
                } else {
                    full_slice
                }
            };

            let ins =
                ProgramDecoder::decode_instruction(instruction_blob, current_pc, skip_distance)?;

            let single_invocation_result =
                Self::single_step_invocation(vm_state, program_state, &ins)?;

            Self::apply_state_change(vm_state, single_invocation_result.state_change)?;
            match single_invocation_result.exit_reason {
                ExitReason::Continue => continue,
                ExitReason::OutOfGas => return Ok(ExitReason::OutOfGas),
                other => return Ok(other),
            }
        }
    }

    /// Single-step PVM state transition function.
    ///
    /// Refers to the VM states e.g. `pc`, `memory`, `instructions` from the `PVMCore` state
    /// and returns the VM state change as an output.
    ///
    /// Instruction `SBRK` is the only instruction that directly mutates the VM state, for a heap expansion.
    ///
    /// Represents `Ψ_1` of the GP.
    fn single_step_invocation(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        match ins.op {
            Opcode::TRAP => IS::trap(vm_state, program_state),
            Opcode::FALLTHROUGH => IS::fallthrough(vm_state, program_state),
            Opcode::ECALLI => IS::ecalli(vm_state, program_state, ins),
            Opcode::STORE_IMM_U8 => IS::store_imm_u8(vm_state, program_state, ins),
            Opcode::STORE_IMM_U16 => IS::store_imm_u16(vm_state, program_state, ins),
            Opcode::STORE_IMM_U32 => IS::store_imm_u32(vm_state, program_state, ins),
            Opcode::JUMP => IS::jump(vm_state, program_state, ins),
            Opcode::JUMP_IND => IS::jump_ind(vm_state, program_state, ins),
            Opcode::LOAD_IMM => IS::load_imm(vm_state, program_state, ins),
            Opcode::LOAD_U8 => IS::load_u8(vm_state, program_state, ins),
            Opcode::LOAD_I8 => IS::load_i8(vm_state, program_state, ins),
            Opcode::LOAD_U16 => IS::load_u16(vm_state, program_state, ins),
            Opcode::LOAD_I16 => IS::load_i16(vm_state, program_state, ins),
            Opcode::LOAD_U32 => IS::load_u32(vm_state, program_state, ins),
            Opcode::STORE_U8 => IS::store_u8(vm_state, program_state, ins),
            Opcode::STORE_U16 => IS::store_u16(vm_state, program_state, ins),
            Opcode::STORE_U32 => IS::store_u32(vm_state, program_state, ins),
            Opcode::STORE_IMM_IND_U8 => IS::store_imm_ind_u8(vm_state, program_state, ins),
            Opcode::STORE_IMM_IND_U16 => IS::store_imm_ind_u16(vm_state, program_state, ins),
            Opcode::STORE_IMM_IND_U32 => IS::store_imm_ind_u32(vm_state, program_state, ins),
            Opcode::LOAD_IMM_JUMP => IS::load_imm_jump(vm_state, program_state, ins),
            Opcode::BRANCH_EQ_IMM => IS::branch_eq_imm(vm_state, program_state, ins),
            Opcode::BRANCH_NE_IMM => IS::branch_ne_imm(vm_state, program_state, ins),
            Opcode::BRANCH_LT_U_IMM => IS::branch_lt_u_imm(vm_state, program_state, ins),
            Opcode::BRANCH_LE_U_IMM => IS::branch_le_u_imm(vm_state, program_state, ins),
            Opcode::BRANCH_GE_U_IMM => IS::branch_ge_u_imm(vm_state, program_state, ins),
            Opcode::BRANCH_GT_U_IMM => IS::branch_gt_u_imm(vm_state, program_state, ins),
            Opcode::BRANCH_LT_S_IMM => IS::branch_lt_s_imm(vm_state, program_state, ins),
            Opcode::BRANCH_LE_S_IMM => IS::branch_le_s_imm(vm_state, program_state, ins),
            Opcode::BRANCH_GE_S_IMM => IS::branch_ge_s_imm(vm_state, program_state, ins),
            Opcode::BRANCH_GT_S_IMM => IS::branch_gt_s_imm(vm_state, program_state, ins),
            Opcode::MOVE_REG => IS::move_reg(vm_state, program_state, ins),
            Opcode::SBRK => IS::sbrk(vm_state, program_state, ins),
            Opcode::STORE_IND_U8 => IS::store_ind_u8(vm_state, program_state, ins),
            Opcode::STORE_IND_U16 => IS::store_ind_u16(vm_state, program_state, ins),
            Opcode::STORE_IND_U32 => IS::store_ind_u32(vm_state, program_state, ins),
            Opcode::LOAD_IND_U8 => IS::load_ind_u8(vm_state, program_state, ins),
            Opcode::LOAD_IND_I8 => IS::load_ind_i8(vm_state, program_state, ins),
            Opcode::LOAD_IND_U16 => IS::load_ind_u16(vm_state, program_state, ins),
            Opcode::LOAD_IND_I16 => IS::load_ind_i16(vm_state, program_state, ins),
            Opcode::LOAD_IND_U32 => IS::load_ind_u32(vm_state, program_state, ins),
            Opcode::ADD_IMM => IS::add_imm(vm_state, program_state, ins),
            Opcode::AND_IMM => IS::and_imm(vm_state, program_state, ins),
            Opcode::XOR_IMM => IS::xor_imm(vm_state, program_state, ins),
            Opcode::OR_IMM => IS::or_imm(vm_state, program_state, ins),
            Opcode::MUL_IMM => IS::mul_imm(vm_state, program_state, ins),
            Opcode::MUL_UPPER_SS_IMM => IS::mul_upper_s_s_imm(vm_state, program_state, ins),
            Opcode::MUL_UPPER_UU_IMM => IS::mul_upper_u_u_imm(vm_state, program_state, ins),
            Opcode::SET_LT_U_IMM => IS::set_lt_u_imm(vm_state, program_state, ins),
            Opcode::SET_LT_S_IMM => IS::set_lt_s_imm(vm_state, program_state, ins),
            Opcode::SHLO_L_IMM => IS::shlo_l_imm(vm_state, program_state, ins),
            Opcode::SHLO_R_IMM => IS::shlo_r_imm(vm_state, program_state, ins),
            Opcode::SHAR_R_IMM => IS::shar_r_imm(vm_state, program_state, ins),
            Opcode::NEG_ADD_IMM => IS::neg_add_imm(vm_state, program_state, ins),
            Opcode::SET_GT_U_IMM => IS::set_gt_u_imm(vm_state, program_state, ins),
            Opcode::SET_GT_S_IMM => IS::set_gt_s_imm(vm_state, program_state, ins),
            Opcode::SHLO_L_IMM_ALT => IS::shlo_l_imm_alt(vm_state, program_state, ins),
            Opcode::SHLO_R_IMM_ALT => IS::shlo_r_imm_alt(vm_state, program_state, ins),
            Opcode::SHAR_R_IMM_ALT => IS::shar_r_imm_alt(vm_state, program_state, ins),
            Opcode::CMOV_IZ_IMM => IS::cmov_iz_imm(vm_state, program_state, ins),
            Opcode::CMOV_NZ_IMM => IS::cmov_nz_imm(vm_state, program_state, ins),
            Opcode::BRANCH_EQ => IS::branch_eq(vm_state, program_state, ins),
            Opcode::BRANCH_NE => IS::branch_ne(vm_state, program_state, ins),
            Opcode::BRANCH_LT_U => IS::branch_lt_u(vm_state, program_state, ins),
            Opcode::BRANCH_LT_S => IS::branch_lt_s(vm_state, program_state, ins),
            Opcode::BRANCH_GE_U => IS::branch_ge_u(vm_state, program_state, ins),
            Opcode::BRANCH_GE_S => IS::branch_ge_s(vm_state, program_state, ins),
            Opcode::LOAD_IMM_JUMP_IND => IS::load_imm_jump_ind(vm_state, program_state, ins),
            Opcode::ADD => IS::add(vm_state, program_state, ins),
            Opcode::SUB => IS::sub(vm_state, program_state, ins),
            Opcode::AND => IS::and(vm_state, program_state, ins),
            Opcode::XOR => IS::xor(vm_state, program_state, ins),
            Opcode::OR => IS::or(vm_state, program_state, ins),
            Opcode::MUL => IS::mul(vm_state, program_state, ins),
            Opcode::MUL_UPPER_SS => IS::mul_upper_s_s(vm_state, program_state, ins),
            Opcode::MUL_UPPER_UU => IS::mul_upper_u_u(vm_state, program_state, ins),
            Opcode::MUL_UPPER_SU => IS::mul_upper_s_u(vm_state, program_state, ins),
            Opcode::DIV_U => IS::div_u(vm_state, program_state, ins),
            Opcode::DIV_S => IS::div_s(vm_state, program_state, ins),
            Opcode::REM_U => IS::rem_u(vm_state, program_state, ins),
            Opcode::REM_S => IS::rem_s(vm_state, program_state, ins),
            Opcode::SET_LT_U => IS::set_lt_u(vm_state, program_state, ins),
            Opcode::SET_LT_S => IS::set_lt_s(vm_state, program_state, ins),
            Opcode::SHLO_L => IS::shlo_l(vm_state, program_state, ins),
            Opcode::SHLO_R => IS::shlo_r(vm_state, program_state, ins),
            Opcode::SHAR_R => IS::shar_r(vm_state, program_state, ins),
            Opcode::CMOV_IZ => IS::cmov_iz(vm_state, program_state, ins),
            Opcode::CMOV_NZ => IS::cmov_nz(vm_state, program_state, ins),
        }
    }
}
