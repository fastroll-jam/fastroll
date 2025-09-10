use crate::{
    error::VMCoreError,
    program::{
        instruction::{opcode::Opcode as OP, set::InstructionSet as IS, Instruction},
        loader::ProgramLoader,
        types::program_state::ProgramState,
    },
    state::{
        state_change::{VMStateChange, VMStateMutator},
        vm_state::VMState,
    },
};
use bit_vec::BitVec;
use fr_pvm_types::{
    common::RegValue,
    constants::{MAX_INST_BLOB_LENGTH, MAX_SKIP_DISTANCE},
    exit_reason::ExitReason,
};

#[derive(Debug)]
pub struct SingleStepResult {
    pub exit_reason: ExitReason,
    pub state_change: VMStateChange,
}

pub struct Interpreter;
impl Interpreter {
    /// Skip function that calculates skip distance to the next instruction from the instruction
    /// sequence and the opcode bitmask
    pub(crate) fn skip(curr_opcode_index: usize, opcode_bitmask: &BitVec) -> usize {
        for skip_distance in 0..=MAX_SKIP_DISTANCE {
            if opcode_bitmask
                .get(curr_opcode_index + 1 + skip_distance)
                .unwrap_or(true)
            {
                return skip_distance;
            }
        }

        MAX_SKIP_DISTANCE // Note: this case implies malformed program.
    }

    /// Get the next pc value from the current VM state and the skip function
    /// for normal instruction execution completion
    #[inline(always)]
    pub fn next_pc(vm_state: &VMState, program_state: &ProgramState) -> RegValue {
        vm_state.pc
            + 1
            + Self::skip(vm_state.pc as usize, &program_state.opcode_bitmask) as RegValue
    }

    /// Extracts a single instruction at a given program counter from the instructions blob.
    /// Returns `None` if the parsing fails.
    fn extract_single_inst(
        instructions: &[u8],
        curr_pc: RegValue,
        skip_distance: usize,
    ) -> Option<Instruction> {
        let curr_ins_idx = curr_pc as usize;
        let next_ins_idx = curr_ins_idx + 1 + skip_distance;

        // Out of instructions slice boundary should be interpreted as TRAP.
        if next_ins_idx > instructions.len() {
            return Some(Instruction::trap());
        }

        let mut inst_blob = &instructions[curr_ins_idx..next_ins_idx];

        // Instruction blob length is not greater than `MAX_INST_BLOB_LENGTH`
        if inst_blob.len() > MAX_INST_BLOB_LENGTH {
            inst_blob = &inst_blob[..MAX_INST_BLOB_LENGTH];
        }

        Instruction::from_inst_blob(inst_blob, curr_pc, skip_distance).ok()
    }

    /// General PVM invocation function.
    ///
    /// This function recursively calls single-step invocation functions following the instruction
    /// sequence mutating the VM states.
    ///
    /// # Input Program
    /// This function utilizes the program component of the `PVM` state. The program is decoded
    /// into instructions sequence, an opcode bitmask, and a dynamic jump table, which are then passed
    /// as arguments to the `invoke_single_step` function.
    ///
    /// Represents `Ψ` of the GP.
    pub fn invoke_general(
        vm_state: &mut VMState,
        program_state: &mut ProgramState, // program code loaded from the `invoke_extended`
        program_code: &[u8],
    ) -> Result<ExitReason, VMCoreError> {
        // Ensure the program state is initialized only once, as the general invocation
        // is triggered within a loop during the extended invocation.
        if !program_state.is_loaded {
            ProgramLoader::load_program(program_code, program_state)?;
        }

        loop {
            let curr_pc = vm_state.pc;
            let skip_distance = Self::skip(curr_pc as usize, &program_state.opcode_bitmask);
            let Some(inst) =
                Self::extract_single_inst(&program_state.instructions, curr_pc, skip_distance)
            else {
                return Ok(ExitReason::Panic);
            };

            let single_invocation_result =
                Self::invoke_single_step(vm_state, program_state, &inst)?;
            let post_gas = match VMStateMutator::apply_state_change(
                vm_state,
                &single_invocation_result.state_change,
            ) {
                Ok(post_gas) => post_gas,
                Err(VMCoreError::InvalidMemZone) => return Ok(ExitReason::Panic),
                Err(VMCoreError::PageFault(page_start_address)) => {
                    vm_state.pc = 0; // TODO: PVM Revisit: (test vectors assume page-fault resets pc value but not in GP)
                    return Ok(ExitReason::PageFault(page_start_address));
                }
                Err(e) => return Err(e),
            };
            if post_gas < 0 {
                return Ok(ExitReason::OutOfGas);
            }

            tracing::trace!(
                "{:?}({}) pc={} gas={} regs={:?}",
                inst.op,
                inst.op as u8,
                vm_state.pc,
                vm_state.gas_counter,
                vm_state.regs
            );

            match single_invocation_result.exit_reason {
                ExitReason::Continue => continue,
                termination @ (ExitReason::Panic | ExitReason::RegularHalt) => {
                    // Reset the program counter
                    // vm_state.pc = 0; // TODO: PVM Revisit: (test vectors assume panic/halt doesn't reset pc value but not in GP)
                    return Ok(termination);
                }
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
    fn invoke_single_step(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        match ins.op {
            OP::TRAP => IS::trap(vm_state, program_state),
            OP::FALLTHROUGH => IS::fallthrough(vm_state, program_state),
            OP::ECALLI => IS::ecalli(vm_state, program_state, ins),
            OP::LOAD_IMM_64 => IS::load_imm_64(vm_state, program_state, ins),
            OP::STORE_IMM_U8 => IS::store_imm_u8(vm_state, program_state, ins),
            OP::STORE_IMM_U16 => IS::store_imm_u16(vm_state, program_state, ins),
            OP::STORE_IMM_U32 => IS::store_imm_u32(vm_state, program_state, ins),
            OP::STORE_IMM_U64 => IS::store_imm_u64(vm_state, program_state, ins),
            OP::JUMP => IS::jump(vm_state, program_state, ins),
            OP::JUMP_IND => IS::jump_ind(vm_state, program_state, ins),
            OP::LOAD_IMM => IS::load_imm(vm_state, program_state, ins),
            OP::LOAD_U8 => IS::load_u8(vm_state, program_state, ins),
            OP::LOAD_I8 => IS::load_i8(vm_state, program_state, ins),
            OP::LOAD_U16 => IS::load_u16(vm_state, program_state, ins),
            OP::LOAD_I16 => IS::load_i16(vm_state, program_state, ins),
            OP::LOAD_U32 => IS::load_u32(vm_state, program_state, ins),
            OP::LOAD_I32 => IS::load_i32(vm_state, program_state, ins),
            OP::LOAD_U64 => IS::load_u64(vm_state, program_state, ins),
            OP::STORE_U8 => IS::store_u8(vm_state, program_state, ins),
            OP::STORE_U16 => IS::store_u16(vm_state, program_state, ins),
            OP::STORE_U32 => IS::store_u32(vm_state, program_state, ins),
            OP::STORE_U64 => IS::store_u64(vm_state, program_state, ins),
            OP::STORE_IMM_IND_U8 => IS::store_imm_ind_u8(vm_state, program_state, ins),
            OP::STORE_IMM_IND_U16 => IS::store_imm_ind_u16(vm_state, program_state, ins),
            OP::STORE_IMM_IND_U32 => IS::store_imm_ind_u32(vm_state, program_state, ins),
            OP::STORE_IMM_IND_U64 => IS::store_imm_ind_u64(vm_state, program_state, ins),
            OP::LOAD_IMM_JUMP => IS::load_imm_jump(vm_state, program_state, ins),
            OP::BRANCH_EQ_IMM => IS::branch_eq_imm(vm_state, program_state, ins),
            OP::BRANCH_NE_IMM => IS::branch_ne_imm(vm_state, program_state, ins),
            OP::BRANCH_LT_U_IMM => IS::branch_lt_u_imm(vm_state, program_state, ins),
            OP::BRANCH_LE_U_IMM => IS::branch_le_u_imm(vm_state, program_state, ins),
            OP::BRANCH_GE_U_IMM => IS::branch_ge_u_imm(vm_state, program_state, ins),
            OP::BRANCH_GT_U_IMM => IS::branch_gt_u_imm(vm_state, program_state, ins),
            OP::BRANCH_LT_S_IMM => IS::branch_lt_s_imm(vm_state, program_state, ins),
            OP::BRANCH_LE_S_IMM => IS::branch_le_s_imm(vm_state, program_state, ins),
            OP::BRANCH_GE_S_IMM => IS::branch_ge_s_imm(vm_state, program_state, ins),
            OP::BRANCH_GT_S_IMM => IS::branch_gt_s_imm(vm_state, program_state, ins),
            OP::MOVE_REG => IS::move_reg(vm_state, program_state, ins),
            OP::SBRK => IS::sbrk(vm_state, program_state, ins),
            OP::COUNT_SET_BITS_64 => IS::count_set_bits_64(vm_state, program_state, ins),
            OP::COUNT_SET_BITS_32 => IS::count_set_bits_32(vm_state, program_state, ins),
            OP::LEADING_ZERO_BITS_64 => IS::leading_zero_bits_64(vm_state, program_state, ins),
            OP::LEADING_ZERO_BITS_32 => IS::leading_zero_bits_32(vm_state, program_state, ins),
            OP::TRAILING_ZERO_BITS_64 => IS::trailing_zero_bits_64(vm_state, program_state, ins),
            OP::TRAILING_ZERO_BITS_32 => IS::trailing_zero_bits_32(vm_state, program_state, ins),
            OP::SIGN_EXTEND_8 => IS::sign_extend_8(vm_state, program_state, ins),
            OP::SIGN_EXTEND_16 => IS::sign_extend_16(vm_state, program_state, ins),
            OP::ZERO_EXTEND_16 => IS::zero_extend_16(vm_state, program_state, ins),
            OP::REVERSE_BYTES => IS::reverse_bytes(vm_state, program_state, ins),
            OP::STORE_IND_U8 => IS::store_ind_u8(vm_state, program_state, ins),
            OP::STORE_IND_U16 => IS::store_ind_u16(vm_state, program_state, ins),
            OP::STORE_IND_U32 => IS::store_ind_u32(vm_state, program_state, ins),
            OP::STORE_IND_U64 => IS::store_ind_u64(vm_state, program_state, ins),
            OP::LOAD_IND_U8 => IS::load_ind_u8(vm_state, program_state, ins),
            OP::LOAD_IND_I8 => IS::load_ind_i8(vm_state, program_state, ins),
            OP::LOAD_IND_U16 => IS::load_ind_u16(vm_state, program_state, ins),
            OP::LOAD_IND_I16 => IS::load_ind_i16(vm_state, program_state, ins),
            OP::LOAD_IND_U32 => IS::load_ind_u32(vm_state, program_state, ins),
            OP::LOAD_IND_I32 => IS::load_ind_i32(vm_state, program_state, ins),
            OP::LOAD_IND_U64 => IS::load_ind_u64(vm_state, program_state, ins),
            OP::ADD_IMM_32 => IS::add_imm_32(vm_state, program_state, ins),
            OP::AND_IMM => IS::and_imm(vm_state, program_state, ins),
            OP::XOR_IMM => IS::xor_imm(vm_state, program_state, ins),
            OP::OR_IMM => IS::or_imm(vm_state, program_state, ins),
            OP::MUL_IMM_32 => IS::mul_imm_32(vm_state, program_state, ins),
            OP::SET_LT_U_IMM => IS::set_lt_u_imm(vm_state, program_state, ins),
            OP::SET_LT_S_IMM => IS::set_lt_s_imm(vm_state, program_state, ins),
            OP::SHLO_L_IMM_32 => IS::shlo_l_imm_32(vm_state, program_state, ins),
            OP::SHLO_R_IMM_32 => IS::shlo_r_imm_32(vm_state, program_state, ins),
            OP::SHAR_R_IMM_32 => IS::shar_r_imm_32(vm_state, program_state, ins),
            OP::NEG_ADD_IMM_32 => IS::neg_add_imm_32(vm_state, program_state, ins),
            OP::SET_GT_U_IMM => IS::set_gt_u_imm(vm_state, program_state, ins),
            OP::SET_GT_S_IMM => IS::set_gt_s_imm(vm_state, program_state, ins),
            OP::SHLO_L_IMM_ALT_32 => IS::shlo_l_imm_alt_32(vm_state, program_state, ins),
            OP::SHLO_R_IMM_ALT_32 => IS::shlo_r_imm_alt_32(vm_state, program_state, ins),
            OP::SHAR_R_IMM_ALT_32 => IS::shar_r_imm_alt_32(vm_state, program_state, ins),
            OP::CMOV_IZ_IMM => IS::cmov_iz_imm(vm_state, program_state, ins),
            OP::CMOV_NZ_IMM => IS::cmov_nz_imm(vm_state, program_state, ins),
            OP::ADD_IMM_64 => IS::add_imm_64(vm_state, program_state, ins),
            OP::MUL_IMM_64 => IS::mul_imm_64(vm_state, program_state, ins),
            OP::SHLO_L_IMM_64 => IS::shlo_l_imm_64(vm_state, program_state, ins),
            OP::SHLO_R_IMM_64 => IS::shlo_r_imm_64(vm_state, program_state, ins),
            OP::SHAR_R_IMM_64 => IS::shar_r_imm_64(vm_state, program_state, ins),
            OP::NEG_ADD_IMM_64 => IS::neg_add_imm_64(vm_state, program_state, ins),
            OP::SHLO_L_IMM_ALT_64 => IS::shlo_l_imm_alt_64(vm_state, program_state, ins),
            OP::SHLO_R_IMM_ALT_64 => IS::shlo_r_imm_alt_64(vm_state, program_state, ins),
            OP::SHAR_R_IMM_ALT_64 => IS::shar_r_imm_alt_64(vm_state, program_state, ins),
            OP::ROT_R_64_IMM => IS::rot_r_64_imm(vm_state, program_state, ins),
            OP::ROT_R_64_IMM_ALT => IS::rot_r_64_imm_alt(vm_state, program_state, ins),
            OP::ROT_R_32_IMM => IS::rot_r_32_imm(vm_state, program_state, ins),
            OP::ROT_R_32_IMM_ALT => IS::rot_r_32_imm_alt(vm_state, program_state, ins),
            OP::BRANCH_EQ => IS::branch_eq(vm_state, program_state, ins),
            OP::BRANCH_NE => IS::branch_ne(vm_state, program_state, ins),
            OP::BRANCH_LT_U => IS::branch_lt_u(vm_state, program_state, ins),
            OP::BRANCH_LT_S => IS::branch_lt_s(vm_state, program_state, ins),
            OP::BRANCH_GE_U => IS::branch_ge_u(vm_state, program_state, ins),
            OP::BRANCH_GE_S => IS::branch_ge_s(vm_state, program_state, ins),
            OP::LOAD_IMM_JUMP_IND => IS::load_imm_jump_ind(vm_state, program_state, ins),
            OP::ADD_32 => IS::add_32(vm_state, program_state, ins),
            OP::SUB_32 => IS::sub_32(vm_state, program_state, ins),
            OP::MUL_32 => IS::mul_32(vm_state, program_state, ins),
            OP::DIV_U_32 => IS::div_u_32(vm_state, program_state, ins),
            OP::DIV_S_32 => IS::div_s_32(vm_state, program_state, ins),
            OP::REM_U_32 => IS::rem_u_32(vm_state, program_state, ins),
            OP::REM_S_32 => IS::rem_s_32(vm_state, program_state, ins),
            OP::SHLO_L_32 => IS::shlo_l_32(vm_state, program_state, ins),
            OP::SHLO_R_32 => IS::shlo_r_32(vm_state, program_state, ins),
            OP::SHAR_R_32 => IS::shar_r_32(vm_state, program_state, ins),
            OP::ADD_64 => IS::add_64(vm_state, program_state, ins),
            OP::SUB_64 => IS::sub_64(vm_state, program_state, ins),
            OP::MUL_64 => IS::mul_64(vm_state, program_state, ins),
            OP::DIV_U_64 => IS::div_u_64(vm_state, program_state, ins),
            OP::DIV_S_64 => IS::div_s_64(vm_state, program_state, ins),
            OP::REM_U_64 => IS::rem_u_64(vm_state, program_state, ins),
            OP::REM_S_64 => IS::rem_s_64(vm_state, program_state, ins),
            OP::SHLO_L_64 => IS::shlo_l_64(vm_state, program_state, ins),
            OP::SHLO_R_64 => IS::shlo_r_64(vm_state, program_state, ins),
            OP::SHAR_R_64 => IS::shar_r_64(vm_state, program_state, ins),
            OP::AND => IS::and(vm_state, program_state, ins),
            OP::XOR => IS::xor(vm_state, program_state, ins),
            OP::OR => IS::or(vm_state, program_state, ins),
            OP::MUL_UPPER_S_S => IS::mul_upper_s_s(vm_state, program_state, ins),
            OP::MUL_UPPER_U_U => IS::mul_upper_u_u(vm_state, program_state, ins),
            OP::MUL_UPPER_S_U => IS::mul_upper_s_u(vm_state, program_state, ins),
            OP::SET_LT_U => IS::set_lt_u(vm_state, program_state, ins),
            OP::SET_LT_S => IS::set_lt_s(vm_state, program_state, ins),
            OP::CMOV_IZ => IS::cmov_iz(vm_state, program_state, ins),
            OP::CMOV_NZ => IS::cmov_nz(vm_state, program_state, ins),
            OP::ROT_L_64 => IS::rot_l_64(vm_state, program_state, ins),
            OP::ROT_L_32 => IS::rot_l_32(vm_state, program_state, ins),
            OP::ROT_R_64 => IS::rot_r_64(vm_state, program_state, ins),
            OP::ROT_R_32 => IS::rot_r_32(vm_state, program_state, ins),
            OP::AND_INV => IS::and_inv(vm_state, program_state, ins),
            OP::OR_INV => IS::or_inv(vm_state, program_state, ins),
            OP::XNOR => IS::xnor(vm_state, program_state, ins),
            OP::MAX => IS::max(vm_state, program_state, ins),
            OP::MAX_U => IS::max_u(vm_state, program_state, ins),
            OP::MIN => IS::min(vm_state, program_state, ins),
            OP::MIN_U => IS::min_u(vm_state, program_state, ins),
        }
    }
}
