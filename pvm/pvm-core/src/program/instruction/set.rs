use crate::{
    error::VMCoreError,
    interpreter::{Interpreter, SingleStepResult},
    program::{instruction::Instruction, types::program_state::ProgramState},
    state::{
        state_change::{MemWrite, VMStateChange},
        vm_state::VMState,
    },
    utils::{SextInputSize, VMUtils},
};
use fr_codec::prelude::*;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::JUMP_ALIGNMENT,
    exit_reason::ExitReason,
    hostcall::HostCallType,
};

// Convert RegValue to smaller int types by taking the lower bits
fn reg_to_mem_address(reg: RegValue) -> MemAddress {
    reg as MemAddress
}

fn reg_to_u8(reg: RegValue) -> u8 {
    reg as u8
}

fn reg_to_u16(reg: RegValue) -> u16 {
    reg as u16
}

fn reg_to_u32(reg: RegValue) -> u32 {
    reg as u32
}

#[allow(clippy::useless_conversion)]
fn reg_to_u64(reg: RegValue) -> u64 {
    reg
}

fn reg_to_usize(reg: RegValue) -> usize {
    reg as usize
}

/// A collection of single-step PVM instruction execution functions.
pub struct InstructionSet;
impl InstructionSet {
    //
    // Group 0: Helper functions
    //

    /// Determines the next instruction counter based on a branch condition.
    ///
    /// If the condition is true, attempts to jump to the target address.
    /// The target address must be the beginning of a basic block.
    fn branch(
        vm_state: &VMState,
        program_state: &ProgramState,
        target: MemAddress,
        condition: bool,
    ) -> Result<(ExitReason, MemAddress), VMCoreError> {
        match (
            condition,
            program_state
                .basic_block_start_indices
                .contains(&(target as usize)),
        ) {
            (false, _) => Ok((
                ExitReason::Continue,
                reg_to_mem_address(Interpreter::next_pc(vm_state, program_state)),
            )),
            (true, true) => Ok((ExitReason::Continue, target)),
            (true, false) => Ok((
                ExitReason::Panic,
                reg_to_mem_address(Interpreter::next_pc(vm_state, program_state)),
            )),
        }
    }

    /// Performs a dynamic jump operation.
    ///
    /// This function handles jumps where the next instruction is dynamically computed.
    /// The jump address is derived from the jump table, with special handling for memory alignment
    /// and validity checks. Specifically, the dynamic addresses are set as jump table indices
    /// incremented by one and multiplied by the `JUMP_ALIGNMENT`.
    pub fn djump(
        vm_state: &VMState,
        program_state: &ProgramState,
        a: usize,
    ) -> Result<(ExitReason, MemAddress), VMCoreError> {
        const SPECIAL_HALT_VALUE: usize = (1 << 32) - (1 << 16);

        if a == SPECIAL_HALT_VALUE {
            return Ok((
                ExitReason::RegularHalt,
                reg_to_mem_address(Interpreter::next_pc(vm_state, program_state)),
            ));
        }

        let jump_table_len = program_state.jump_table.len();

        // Check if the argument `a` is valid and compute the target
        if a == 0 || a > jump_table_len * JUMP_ALIGNMENT || a % JUMP_ALIGNMENT != 0 {
            return Ok((
                ExitReason::Panic,
                reg_to_mem_address(Interpreter::next_pc(vm_state, program_state)),
            ));
        }

        let aligned_index = (a / JUMP_ALIGNMENT)
            .checked_sub(1)
            .expect("`a` should be larger than zero");
        let &target = program_state
            .jump_table
            .get(aligned_index)
            .ok_or(VMCoreError::JumpTableOutOfBounds(aligned_index))?;

        if program_state
            .basic_block_start_indices
            .contains(&(target as usize))
        {
            Ok((ExitReason::Continue, target))
        } else {
            Ok((
                ExitReason::Panic,
                reg_to_mem_address(Interpreter::next_pc(vm_state, program_state)),
            ))
        }
    }

    //
    // Group 1: Instructions without Arguments
    //

    /// `panic` with no mutation to the VM state
    ///
    /// Opcode: 0
    pub fn trap(
        vm_state: &VMState,
        program_state: &ProgramState,
    ) -> Result<SingleStepResult, VMCoreError> {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Panic,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Continue program with no mutation to the VM state
    ///
    /// Opcode: 1
    pub fn fallthrough(
        vm_state: &VMState,
        program_state: &ProgramState,
    ) -> Result<SingleStepResult, VMCoreError> {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 2: Instructions with Arguments of One Immediate
    //

    /// Invoke host function call
    ///
    /// Opcode: 10
    pub fn ecalli(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_host_call_type = reg_to_u8(ins.imm1()?);

        let exit_reason = ExitReason::HostCall(
            HostCallType::from_u8(imm_host_call_type).ok_or(VMCoreError::InvalidHostCallType)?,
        );

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 3: Instructions with Arguments of One Register and One Extended Width Immediate
    //

    /// Load a 64-bit immediate value into a register
    ///
    /// Opcode: 20
    pub fn load_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc(vm_state, program_state),
                register_write: Some((ins.rs1()?, reg_to_u64(ins.imm1()?))),
                ..Default::default()
            },
        })
    }

    //
    // Group 4: Instructions with Arguments of Two Immediates
    //

    /// Store immediate argument value to the memory as `u8` integer type
    ///
    /// Opcode: 30
    pub fn store_imm_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let imm_value = ins.imm2()?;
        let value = vec![(imm_value & 0xFF) as u8]; // mod 2^8

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate argument value to the memory as `u16` integer type
    ///
    /// Opcode: 31
    pub fn store_imm_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let imm_value = ins.imm2()?;
        let value = ((imm_value & 0xFFFF) as u16).encode_fixed(2)?; // mod 2^16

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate argument value to the memory as `u32` integer type
    ///
    /// Opcode: 32
    pub fn store_imm_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let imm_value = ins.imm2()?;
        let value = ((imm_value & 0xFFFF_FFFF) as u32).encode_fixed(4)?; // mod 2^32

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate argument value to the memory as `u64` integer type
    ///
    /// Opcode: 33
    pub fn store_imm_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let imm_value = ins.imm2()?;
        let value = imm_value.encode_fixed(8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 5: Instructions with Arguments of One Offset
    //

    /// Jump to the target address with no condition checks
    ///
    /// Opcode: 40
    pub fn jump(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        tracing::trace!("{:?} target: {target}\n", ins.op);
        let (exit_reason, target) = Self::branch(vm_state, program_state, target, true)?;

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    //
    // Group 6: Instructions with Arguments of One Register & One Immediate
    //

    /// Jump to an address stored in a register plus an immediate offset
    ///
    /// Indirect jump instruction. It adds the value in the specified
    /// register to an immediate value offset, then jumps to the resulting address.
    ///
    /// Opcode: 50
    pub fn jump_ind(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let imm1 = ins.imm1()?;
        let jump_address = reg_to_usize(rs1_val.wrapping_add(imm1) & 0xFFFF_FFFF);
        let (exit_reason, target) = Self::djump(vm_state, program_state, jump_address)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Load an immediate value into a register
    ///
    /// Opcode: 51
    pub fn load_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, ins.imm1()?)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load an unsigned 8-bit value from memory into a register
    ///
    /// Opcode: 52
    pub fn load_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_byte(imm_address)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load a signed 8-bit value from memory into register
    ///
    /// Opcode: 53
    pub fn load_i8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_byte(imm_address)?;
        let val_extended = VMUtils::sext(val, SextInputSize::Octets1);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load unsigned 16-bit value from memory into register
    ///
    /// Opcode: 54
    pub fn load_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_bytes(imm_address, 2)?;
        let val_decoded = RegValue::decode_fixed(&mut &val[..], 2)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_decoded)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load signed 16-bit value from memory into register
    ///
    /// Opcode: 55
    pub fn load_i16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_bytes(imm_address, 2)?;
        let val_decoded = u16::decode_fixed(&mut &val[..], 2)?;
        let val_extended = VMUtils::sext(val_decoded, SextInputSize::Octets2);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load unsigned 32-bit value from memory into register
    ///
    /// Opcode: 56
    pub fn load_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_bytes(imm_address, 4)?;
        let val_decoded = RegValue::decode_fixed(&mut &val[..], 4)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_decoded)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load signed 32-bit value from memory into register
    ///
    /// Opcode: 57
    pub fn load_i32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_bytes(imm_address, 4)?;
        let val_decoded = u32::decode_fixed(&mut &val[..], 4)?;
        let val_extended = VMUtils::sext(val_decoded, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load unsigned 64-bit value from memory into register
    ///
    /// Opcode: 58
    pub fn load_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let val = vm_state.memory.read_bytes(imm_address, 8)?;
        let val_decoded = RegValue::decode_fixed(&mut &val[..], 8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, val_decoded)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store register value to the memory as 8-bit unsigned integer
    ///
    /// Opcode: 59
    pub fn store_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let rs1_val = reg_to_u8(vm_state.read_rs1(ins)? & 0xFF);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, vec![rs1_val])),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store register value to memory as 16-bit unsigned integer
    ///
    /// Opcode: 60
    pub fn store_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let rs1_val = reg_to_u16(vm_state.read_rs1(ins)? & 0xFFFF);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, rs1_val.encode_fixed(2)?)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store register value to memory as 32-bit unsigned integer
    ///
    /// Opcode: 61
    pub fn store_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let rs1_val = reg_to_u32(vm_state.read_rs1(ins)? & 0xFFFF_FFFF);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, rs1_val.encode_fixed(4)?)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store register value to memory as 64-bit unsigned integer
    ///
    /// Opcode: 62
    pub fn store_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let imm_address = reg_to_mem_address(ins.imm1()?);
        let rs1_val = reg_to_u64(vm_state.read_rs1(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(imm_address, rs1_val.encode_fixed(8)?)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 7: Instructions with Arguments of One Register & Two Immediates
    //

    /// Store immediate 8-bit value to memory indirectly
    ///
    /// Opcode: 70
    pub fn store_imm_ind_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs1(ins)?.wrapping_add(ins.imm1()?));
        let value = vec![reg_to_u8(ins.imm2()? & 0xFF)];

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate 16-bit value to memory indirectly
    ///
    /// Opcode: 71
    pub fn store_imm_ind_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs1(ins)?.wrapping_add(ins.imm1()?));
        let value = reg_to_u16(ins.imm2()? & 0xFFFF).encode_fixed(2)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate 32-bit value to memory indirectly
    ///
    /// Opcode: 72
    pub fn store_imm_ind_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs1(ins)?.wrapping_add(ins.imm1()?));
        // TODO: check the GP if `mod 2^32` not needed here
        let value = reg_to_u32(ins.imm2()?).encode_fixed(4)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store immediate 64-bit value to memory indirectly
    ///
    /// Opcode: 73
    pub fn store_imm_ind_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs1(ins)?.wrapping_add(ins.imm1()?));
        let value = reg_to_u64(ins.imm2()?).encode_fixed(8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 8: Instructions with Arguments of One Register, One Immediate and One Offset
    //

    /// Load immediate value and jump to the offset address
    ///
    /// Opcode: 80
    pub fn load_imm_jump(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        tracing::trace!("{:?} target: {target}\n", ins.op);
        let (exit_reason, target) = Self::branch(vm_state, program_state, target, true)?;

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, ins.imm1()?)),
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if equal to immediate
    ///
    /// Opcode: 81
    pub fn branch_eq_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? == ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if not equal to immediate
    ///
    /// Opcode: 82
    pub fn branch_ne_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? != ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than immediate (unsigned)
    ///
    /// Opcode: 83
    pub fn branch_lt_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? < ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than or equal to immediate (unsigned)
    ///
    /// Opcode: 84
    pub fn branch_le_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? <= ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal to immediate (unsigned)
    ///
    /// Opcode: 85
    pub fn branch_ge_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? >= ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than immediate (unsigned)
    ///
    /// Opcode: 86
    pub fn branch_gt_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let condition = vm_state.read_rs1(ins)? > ins.imm1()?;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than immediate (signed)
    ///
    /// Opcode: 87
    pub fn branch_lt_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let imm_val = VMUtils::u64_to_i64(ins.imm1()?);
        let condition = rs1_val < imm_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than or equal to immediate (signed)
    ///
    /// Opcode: 88
    pub fn branch_le_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let imm_val = VMUtils::u64_to_i64(ins.imm1()?);

        let condition = rs1_val <= imm_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal to immediate (signed)
    ///
    /// Opcode: 89
    pub fn branch_ge_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let imm_val = VMUtils::u64_to_i64(ins.imm1()?);
        let condition = rs1_val >= imm_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than immediate (signed)
    ///
    /// Opcode: 90
    pub fn branch_gt_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm2()?);
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let imm_val = VMUtils::u64_to_i64(ins.imm1()?);
        let condition = rs1_val > imm_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    //
    // Group 9: Instructions with Arguments of Two Registers
    //

    /// Move value from one register to another
    ///
    /// Opcode: 100
    pub fn move_reg(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, rs1_val)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// System break (allocate heap memory)
    ///
    /// Expands the heap memory by the requested size.
    ///
    /// Note: this instruction directly mutates the VM memory state unlike other instructions.
    ///
    /// Opcode: 101
    pub fn sbrk(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let expand_size = vm_state.read_rs1(ins)? as usize;

        // find the first sequence of inaccessible memory cells that can satisfy the requested size
        let alloc_start = vm_state.memory.get_break(expand_size)?;

        // try expanding the heap area
        vm_state.memory.expand_heap(alloc_start, expand_size)?;

        // returns the start of the newly allocated heap memory
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, alloc_start as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of set bits of a 64-bit value
    ///
    /// Opcode: 102
    pub fn count_set_bits_64(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let set_bits = VMUtils::u64_to_bits(rs1_val).count_ones();

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, set_bits)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of set bits of a 64-bit value
    ///
    /// Opcode: 103
    pub fn count_set_bits_32(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = reg_to_u32(vm_state.read_rs1(ins)? & 0xFFFF_FFFF);
        let set_bits = VMUtils::u32_to_bits(rs1_val).count_ones();

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, set_bits)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of leading zeroes of a 64-bit value
    ///
    /// Opcode: 104
    pub fn leading_zero_bits_64(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let leading_zeros = rs1_val.leading_zeros() as u64;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, leading_zeros)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of leading zeroes of a 32-bit value
    ///
    /// Opcode: 105
    pub fn leading_zero_bits_32(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = reg_to_u32(vm_state.read_rs1(ins)? & 0xFFFF_FFFF);
        let leading_zeros = rs1_val.leading_zeros() as u64;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, leading_zeros)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of trailing zeroes of a 64-bit value
    ///
    /// Opcode: 106
    pub fn trailing_zero_bits_64(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let trailing_zeros = rs1_val.trailing_zeros() as u64;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, trailing_zeros)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Count the number of trailing zeroes of a 32-bit value
    ///
    /// Opcode: 107
    pub fn trailing_zero_bits_32(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = reg_to_u32(vm_state.read_rs1(ins)? & 0xFFFF_FFFF);
        let trailing_zeros = rs1_val.trailing_zeros() as u64;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, trailing_zeros)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Sign extend a 8-bit value
    ///
    /// Opcode: 108
    pub fn sign_extend_8(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = reg_to_u8(vm_state.read_rs1(ins)? & 0xFF);
        let val = VMUtils::i64_to_u64(VMUtils::u8_to_i8(rs1_val) as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, val)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Sign extend a 16-bit value
    ///
    /// Opcode: 109
    pub fn sign_extend_16(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = reg_to_u16(vm_state.read_rs1(ins)? & 0xFFFF);
        let val = VMUtils::i64_to_u64(VMUtils::u16_to_i16(rs1_val) as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, val)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Zero extend a 16-bit value
    ///
    /// Opcode: 110
    pub fn zero_extend_16(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)? & 0xFFFF;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, rs1_val)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Reverse bytes of a 64-bit value
    ///
    /// Opcode: 111
    pub fn reverse_bytes(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let mut rs1_val_encoded = rs1_val.encode_fixed(8)?;
        rs1_val_encoded.reverse();
        let rev_val = u64::decode_fixed(&mut rs1_val_encoded.as_slice(), 8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, rev_val)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 10: Instructions with Arguments of Two Registers & One Immediate
    //

    /// Store 8-bit value to memory indirectly
    ///
    /// Opcode: 120
    pub fn store_ind_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vec![reg_to_u8(vm_state.read_rs1(ins)? & 0xFF)];

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store 16-bit value to memory indirectly
    ///
    /// Opcode: 121
    pub fn store_ind_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = reg_to_u16(vm_state.read_rs1(ins)? & 0xFFFF).encode_fixed(2)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store 32-bit value to memory indirectly
    ///
    /// Opcode: 122
    pub fn store_ind_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = reg_to_u32(vm_state.read_rs1(ins)? & 0xFFFF_FFFF).encode_fixed(4)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Store 64-bit value to memory indirectly
    ///
    /// Opcode: 123
    pub fn store_ind_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = reg_to_u64(vm_state.read_rs1(ins)?).encode_fixed(8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new(address, value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 8-bit unsigned value from memory indirectly
    ///
    /// Opcode: 124
    pub fn load_ind_u8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_byte(address)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, value as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 8-bit signed value from memory indirectly
    ///
    /// Opcode: 125
    pub fn load_ind_i8(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_byte(address)?;
        let signed_value = VMUtils::u8_to_i8(value);
        let unsigned_value = VMUtils::i64_to_u64(signed_value as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, unsigned_value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 16-bit unsigned value from memory indirectly
    ///
    /// Opcode: 126
    pub fn load_ind_u16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_bytes(address, 2)?;
        let value_decoded = u16::decode_fixed(&mut &value[..], 2)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, value_decoded as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 16-bit signed value from memory indirectly
    ///
    /// Opcode: 127
    pub fn load_ind_i16(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_bytes(address, 2)?;
        let value_decoded = u16::decode_fixed(&mut &value[..], 2)?;
        let signed_value = VMUtils::u16_to_i16(value_decoded);
        let unsigned_value = VMUtils::i64_to_u64(signed_value as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, unsigned_value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 32-bit unsigned value from memory indirectly
    ///
    /// Opcode: 128
    pub fn load_ind_u32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_bytes(address, 4)?;
        let value_decoded = u32::decode_fixed(&mut &value[..], 4)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, value_decoded as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 32-bit signed value from memory indirectly
    ///
    /// Opcode: 129
    pub fn load_ind_i32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_bytes(address, 4)?;
        let value_decoded = u32::decode_fixed(&mut &value[..], 4)?;
        let signed_value = VMUtils::u32_to_i32(value_decoded);
        let unsigned_value = VMUtils::i64_to_u64(signed_value as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, unsigned_value)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Load 64-bit unsigned value from memory indirectly
    ///
    /// Opcode: 130
    pub fn load_ind_u64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let address = reg_to_mem_address(vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?));
        let value = vm_state.memory.read_bytes(address, 8)?;
        let value_decoded = u64::decode_fixed(&mut &value[..], 8)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, value_decoded as RegValue)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Add 32-bit immediate to register value and allocate to another register
    ///
    /// Opcode: 131
    pub fn add_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise AND with immediate
    ///
    /// Opcode: 132
    pub fn and_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)? & ins.imm1()?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise XOR with immediate
    ///
    /// Opcode: 133
    pub fn xor_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)? ^ ins.imm1()?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise OR with immediate
    ///
    /// Opcode: 134
    pub fn or_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)? | ins.imm1()?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply with 32-bit immediate
    ///
    /// Opcode: 135
    pub fn mul_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)?.wrapping_mul(ins.imm1()?);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if less than immediate (unsigned)
    ///
    /// Opcode: 136
    pub fn set_lt_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val = vm_state.read_rs2(ins)?;
        let imm1_val = ins.imm1()?;
        let result = if rs2_val < imm1_val { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if less than immediate (signed)
    ///
    /// Opcode: 137
    pub fn set_lt_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let imm1_val_s = VMUtils::u64_to_i64(ins.imm1()?);

        let result = if rs2_val_s < imm1_val_s { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical with 32-bit immediate
    ///
    /// Opcode: 138
    pub fn shlo_l_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x1F; // mod 32
        let result = vm_state.read_rs2(ins)? << shift;
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical with 32-bit immediate
    ///
    /// Opcode: 139
    pub fn shlo_r_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x1F; // mod 32
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = (rs2_val & 0xFFFF_FFFF) >> shift;
        let result_extended = VMUtils::sext(result, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic with 32-bit immediate
    ///
    /// Opcode: 140
    pub fn shar_r_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x1F; // mod 32
        let rs2_val = vm_state.read_rs2(ins)?;
        let rs2_val_s = VMUtils::u32_to_i32((rs2_val & 0xFFFF_FFFF) as u32);
        let result = rs2_val_s >> shift;
        let result_u = VMUtils::i64_to_u64(result as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Negate and add 32-bit immediate
    ///
    /// Opcode: 141
    pub fn neg_add_imm_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = ins
            .imm1()?
            .wrapping_add(1 << 32)
            .wrapping_sub(vm_state.read_rs2(ins)?);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if greater than immediate (unsigned)
    ///
    /// Opcode: 142
    pub fn set_gt_u_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val = vm_state.read_rs2(ins)?;
        let imm1_val = ins.imm1()?;
        let result = if rs2_val > imm1_val { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if greater than immediate (signed)
    ///
    /// Opcode: 143
    pub fn set_gt_s_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let imm1_val_s = VMUtils::u64_to_i64(ins.imm1()?);

        let result = if rs2_val_s > imm1_val_s { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical with 32-bit immediate (alternative)
    ///
    /// Opcode: 144
    pub fn shlo_l_imm_alt_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let result = ins.imm1()? << shift;

        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical with 32-bit immediate (alternative)
    ///
    /// Opcode: 145
    pub fn shlo_r_imm_alt_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let imm1 = ins.imm1()?;
        let result = (imm1 & 0xFFFF_FFFF) >> shift;
        let result_extended = VMUtils::sext(result, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic with 32-bit immediate (alternative)
    ///
    /// Opcode: 146
    pub fn shar_r_imm_alt_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let imm1 = ins.imm1()?;
        let imm1_val_s = VMUtils::u32_to_i32((imm1 & 0xFFFF_FFFF) as u32);
        let result = imm1_val_s >> shift;
        let result_u = VMUtils::i64_to_u64(result as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Conditional move if zero with immediate
    ///
    /// Opcode: 147
    pub fn cmov_iz_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = if vm_state.read_rs2(ins)? == 0 {
            ins.imm1()?
        } else {
            vm_state.read_rs1(ins)?
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Conditional move if not zero with immediate
    ///
    /// Opcode: 148
    pub fn cmov_nz_imm(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = if vm_state.read_rs2(ins)? != 0 {
            ins.imm1()?
        } else {
            vm_state.read_rs1(ins)?
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Add 64-bit immediate to register value and allocate to another register
    ///
    /// Opcode: 149
    pub fn add_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)?.wrapping_add(ins.imm1()?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply with 64-bit immediate
    ///
    /// Opcode: 150
    pub fn mul_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs2(ins)?.wrapping_mul(ins.imm1()?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical with 64-bit immediate
    ///
    /// Opcode: 151
    pub fn shlo_l_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x3F; // mod 64
        let result = vm_state.read_rs2(ins)? << shift;
        let result_extended = VMUtils::sext(result, SextInputSize::Octets8);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical with 64-bit immediate
    ///
    /// Opcode: 152
    pub fn shlo_r_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x3F; // mod 64
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = rs2_val >> shift;
        let result_extended = VMUtils::sext(result, SextInputSize::Octets8);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic with 64-bit immediate
    ///
    /// Opcode: 153
    pub fn shar_r_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = ins.imm1()? & 0x3F; // mod 64
        let rs2_val = vm_state.read_rs2(ins)?;
        let rs2_val_s = VMUtils::u64_to_i64(rs2_val);
        let result = rs2_val_s >> shift;
        let result_u = VMUtils::i64_to_u64(result);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Negate and add 64-bit immediate
    ///
    /// Opcode: 154
    pub fn neg_add_imm_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = ins.imm1()?.wrapping_sub(vm_state.read_rs2(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical with 64-bit immediate (alternative)
    ///
    /// Opcode: 155
    pub fn shlo_l_imm_alt_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let result = ins.imm1()? << shift;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical with 64-bit immediate (alternative)
    ///
    /// Opcode: 156
    pub fn shlo_r_imm_alt_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let imm1 = ins.imm1()?;
        let result = imm1 >> shift;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic with 64-bit immediate (alternative)
    ///
    /// Opcode: 157
    pub fn shar_r_imm_alt_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let imm1_val_s = VMUtils::u64_to_i64(ins.imm1()?);
        let result = imm1_val_s >> shift;
        let result_u = VMUtils::i64_to_u64(result);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 64-bit value by an immediate amount
    ///
    /// Opcode: 158
    pub fn rot_r_64_imm(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(ins.imm1()?);
        let result = vm_state.read_rs2(ins)?.rotate_right(rotate);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 64-bit value by an immediate amount (alternative)
    ///
    /// Opcode: 159
    pub fn rot_r_64_imm_alt(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = ins.imm1()?.rotate_right(rotate);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 32-bit value by an immediate amount
    ///
    /// Opcode: 160
    pub fn rot_r_32_imm(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(ins.imm1()?);
        let result = VMUtils::sext(
            reg_to_u32(vm_state.read_rs2(ins)?).rotate_right(rotate),
            SextInputSize::Octets4,
        );

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 32-bit value by an immediate amount (alternative)
    ///
    /// Opcode: 161
    pub fn rot_r_32_imm_alt(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = VMUtils::sext(
            reg_to_u32(ins.imm1()?).rotate_right(rotate),
            SextInputSize::Octets4,
        );

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    //
    // Group 11: Instructions with Arguments of Two Registers & One Offset
    //

    /// Branch if equal
    ///
    /// Opcode: 170
    pub fn branch_eq(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let condition = rs1_val == rs2_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if not equal
    ///
    /// Opcode: 171
    pub fn branch_ne(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let condition = rs1_val != rs2_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than (unsigned)
    ///
    /// Opcode: 172
    pub fn branch_lt_u(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let condition = rs1_val < rs2_val;
        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if less than (signed)
    ///
    /// Opcode: 173
    pub fn branch_lt_s(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val_s = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);

        let condition = rs1_val_s < rs2_val_s;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal (unsigned)
    ///
    /// Opcode: 174
    pub fn branch_ge_u(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let condition = rs1_val >= rs2_val;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal (signed)
    ///
    /// Opcode: 175
    pub fn branch_ge_s(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let target = reg_to_mem_address(ins.imm1()?);
        let rs1_val_s = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let condition = rs1_val_s >= rs2_val_s;

        let (exit_reason, target) = Self::branch(vm_state, program_state, target, condition)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    //
    // Group 12: Instructions with Arguments of Two Registers & Two Immediates
    //

    /// Load immediate and jump indirect
    ///
    /// Opcode: 180
    pub fn load_imm_jump_ind(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let jump_address =
            reg_to_usize(vm_state.read_rs2(ins)?.wrapping_add(ins.imm2()?) & 0xFFFF_FFFF);
        let (exit_reason, target) = Self::djump(vm_state, program_state, jump_address)?;
        tracing::trace!("{:?} target: {target}\n", ins.op);

        Ok(SingleStepResult {
            exit_reason,
            state_change: VMStateChange {
                register_write: Some((ins.rs1()?, ins.imm1()?)),
                new_pc: target as RegValue,
                ..Default::default()
            },
        })
    }

    //
    // Group 13: Instructions with Arguments of Three Registers
    //

    /// Add two registers and get a 32-bit value
    ///
    /// Opcode: 190
    pub fn add_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_add(vm_state.read_rs2(ins)?);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Subtract two registers and get a 32-bit value
    ///
    /// Opcode: 191
    pub fn sub_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_add(1 << 32)
            .wrapping_sub(vm_state.read_rs2(ins)? & 0xFFFF_FFFF);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply two registers and get a 32-bit value
    ///
    /// Opcode: 192
    pub fn mul_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_mul(vm_state.read_rs2(ins)?);
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Divide unsigned and get a 32-bit value
    ///
    /// Opcode: 193
    pub fn div_u_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = vm_state.read_rs1(ins)? & 0xFFFF_FFFF;
        let divisor = vm_state.read_rs2(ins)? & 0xFFFF_FFFF;
        let result = if divisor == 0 {
            u64::MAX
        } else {
            VMUtils::sext(dividend / divisor, SextInputSize::Octets4)
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Divide signed and get a 32-bit value
    ///
    /// Opcode: 194
    pub fn div_s_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = VMUtils::u32_to_i32((vm_state.read_rs1(ins)? & 0xFFFF_FFFF) as u32);
        let divisor = VMUtils::u32_to_i32((vm_state.read_rs2(ins)? & 0xFFFF_FFFF) as u32);

        let result = if divisor == 0 {
            u64::MAX
        } else if dividend == i32::MIN && divisor == -1 {
            VMUtils::i64_to_u64(dividend as i64)
        } else {
            VMUtils::i64_to_u64((dividend / divisor) as i64)
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Remainder unsigned and get a 32-bit value
    ///
    /// Opcode: 195
    pub fn rem_u_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = vm_state.read_rs1(ins)? & 0xFFFF_FFFF;
        let divisor = vm_state.read_rs2(ins)? & 0xFFFF_FFFF;
        let result = if divisor == 0 {
            VMUtils::sext(dividend, SextInputSize::Octets4)
        } else {
            VMUtils::sext(dividend % divisor, SextInputSize::Octets4)
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Remainder signed and get a 32-bit value
    ///
    /// Opcode: 196
    pub fn rem_s_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = VMUtils::u32_to_i32((vm_state.read_rs1(ins)? & 0xFFFF_FFFF) as u32);
        let divisor = VMUtils::u32_to_i32((vm_state.read_rs2(ins)? & 0xFFFF_FFFF) as u32);
        let result = if dividend == i32::MIN && divisor == -1 {
            0
        } else {
            VMUtils::i64_to_u64(VMUtils::smod_32(dividend, divisor) as i64)
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical and get a 32-bit value
    ///
    /// Opcode: 197
    pub fn shlo_l_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let result = vm_state.read_rs1(ins)? << shift;
        let result_extended = VMUtils::sext(result & 0xFFFF_FFFF, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical and get a 32-bit value
    ///
    /// Opcode: 198
    pub fn shlo_r_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let result = (vm_state.read_rs1(ins)? & 0xFFFF_FFFF) >> shift;
        let result_extended = VMUtils::sext(result, SextInputSize::Octets4);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_extended)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic and get a 32-bit value
    ///
    /// Opcode: 199
    pub fn shar_r_32(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x1F; // mod 32
        let value = VMUtils::u32_to_i32(((vm_state.read_rs1(ins)?) & 0xFFFF_FFFF) as u32);
        let result = value >> shift;
        let result_u = VMUtils::i64_to_u64(result as i64);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Add two registers and get a 64-bit value
    ///
    /// Opcode: 200
    pub fn add_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_add(vm_state.read_rs2(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Subtract two registers and get a 64-bit value
    ///
    /// Opcode: 201
    pub fn sub_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_sub(vm_state.read_rs2(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply two registers and get a 64-bit value
    ///
    /// Opcode: 202
    pub fn mul_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state
            .read_rs1(ins)?
            .wrapping_mul(vm_state.read_rs2(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Divide unsigned and get a 64-bit value
    ///
    /// Opcode: 203
    pub fn div_u_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = vm_state.read_rs1(ins)?;
        let divisor = vm_state.read_rs2(ins)?;
        let result = if divisor == 0 {
            u64::MAX
        } else {
            dividend / divisor
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Divide signed and get a 64-bit value
    ///
    /// Opcode: 204
    pub fn div_s_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let divisor = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);

        let result = if divisor == 0 {
            u64::MAX
        } else if dividend == i64::MIN && divisor == -1 {
            vm_state.read_rs1(ins)?
        } else {
            VMUtils::i64_to_u64(dividend / divisor)
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Remainder unsigned and get a 64-bit value
    ///
    /// Opcode: 205
    pub fn rem_u_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = vm_state.read_rs1(ins)?;
        let divisor = vm_state.read_rs2(ins)?;
        let result = if divisor == 0 {
            dividend
        } else {
            dividend % divisor
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Remainder signed and get a 64-bit value
    ///
    /// Opcode: 206
    pub fn rem_s_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let dividend = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let divisor = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let result = if dividend == i64::MIN && divisor == -1 {
            0
        } else {
            VMUtils::i64_to_u64(VMUtils::smod_64(dividend, divisor))
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift left logical and get a 64-bit value
    ///
    /// Opcode: 207
    pub fn shlo_l_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let result = vm_state.read_rs1(ins)? << shift;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right logical and get a 64-bit value
    ///
    /// Opcode: 208
    pub fn shlo_r_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let result = vm_state.read_rs1(ins)? >> shift;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic and get a 64-bit value
    ///
    /// Opcode: 209
    pub fn shar_r_64(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let shift = vm_state.read_rs2(ins)? & 0x3F; // mod 64
        let value = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let result = value >> shift;
        let result_u = VMUtils::i64_to_u64(result);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise AND of two registers
    ///
    /// Opcode: 210
    pub fn and(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs1(ins)? & vm_state.read_rs2(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise XOR of two registers
    ///
    /// Opcode: 211
    pub fn xor(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs1(ins)? ^ vm_state.read_rs2(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise OR of two registers
    ///
    /// Opcode: 212
    pub fn or(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs1(ins)? | vm_state.read_rs2(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (signed * signed)
    ///
    /// Opcode: 213
    pub fn mul_upper_s_s(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val_s = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let result = ((rs1_val_s as i128 * rs2_val_s as i128) >> 64) as i64;
        let result_u = VMUtils::i64_to_u64(result);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (unsigned * unsigned)
    ///
    /// Opcode: 214
    pub fn mul_upper_u_u(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = ((rs1_val as u128 * rs2_val as u128) >> 64) as u64;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (signed * unsigned)
    ///
    /// Opcode: 215
    pub fn mul_upper_s_u(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val_s = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = ((rs1_val_s as i128 * rs2_val as i128) >> 64) as i64;
        let result_u = VMUtils::i64_to_u64(result);
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result_u)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if less than (unsigned)
    ///
    /// Opcode: 216
    pub fn set_lt_u(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = if rs1_val < rs2_val { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Set if less than (signed)
    ///
    /// Opcode: 217
    pub fn set_lt_s(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val_s = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val_s = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let result = if rs1_val_s < rs2_val_s { 1 } else { 0 };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Conditional move if zero
    ///
    /// Opcode: 218
    pub fn cmov_iz(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = if rs2_val == 0 {
            vm_state.read_rs1(ins)?
        } else {
            vm_state.read_rd(ins)?
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Conditional move if not zero
    ///
    /// Opcode: 219
    pub fn cmov_nz(
        vm_state: &VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = if rs2_val != 0 {
            vm_state.read_rs1(ins)?
        } else {
            vm_state.read_rd(ins)?
        };

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate left logical a 64-bit value
    ///
    /// Opcode: 220
    pub fn rot_l_64(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = vm_state.read_rs1(ins)?.rotate_left(rotate);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate left logical a 32-bit value
    ///
    /// Opcode: 221
    pub fn rot_l_32(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = VMUtils::sext(
            reg_to_u32(vm_state.read_rs1(ins)?).rotate_left(rotate),
            SextInputSize::Octets4,
        );

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 64-bit value
    ///
    /// Opcode: 222
    pub fn rot_r_64(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = vm_state.read_rs1(ins)?.rotate_right(rotate);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Rotate right logical a 32-bit value
    ///
    /// Opcode: 223
    pub fn rot_r_32(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rotate = reg_to_u32(vm_state.read_rs2(ins)?);
        let result = VMUtils::sext(
            reg_to_u32(vm_state.read_rs1(ins)?).rotate_right(rotate),
            SextInputSize::Octets4,
        );

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise AND with the inverse of the second register.
    ///
    /// Opcode: 224
    pub fn and_inv(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs1(ins)? & !vm_state.read_rs2(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise OR with the inverse of the second register.
    ///
    /// Opcode: 225
    pub fn or_inv(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = vm_state.read_rs1(ins)? | !vm_state.read_rs2(ins)?;

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Bitwise XNOR of two registers.
    ///
    /// Opcode: 226
    pub fn xnor(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let result = !(vm_state.read_rs1(ins)? ^ vm_state.read_rs2(ins)?);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Return the maximum of two signed 64-bit register values
    ///
    /// Opcode: 227
    pub fn max(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let result = VMUtils::i64_to_u64(rs1_val.max(rs2_val));

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Return the maximum of two unsigned 64-bit register values
    ///
    /// Opcode: 228
    pub fn max_u(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = rs1_val.max(rs2_val);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Return the minimum of two signed 64-bit register values
    ///
    /// Opcode: 229
    pub fn min(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = VMUtils::u64_to_i64(vm_state.read_rs1(ins)?);
        let rs2_val = VMUtils::u64_to_i64(vm_state.read_rs2(ins)?);
        let result = VMUtils::i64_to_u64(rs1_val.min(rs2_val));

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }

    /// Return the minimum of two unsigned 64-bit register values
    ///
    /// Opcode: 230
    pub fn min_u(
        vm_state: &mut VMState,
        program_state: &ProgramState,
        ins: &Instruction,
    ) -> Result<SingleStepResult, VMCoreError> {
        let rs1_val = vm_state.read_rs1(ins)?;
        let rs2_val = vm_state.read_rs2(ins)?;
        let result = rs1_val.min(rs2_val);

        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                register_write: Some((ins.rd()?, result)),
                new_pc: Interpreter::next_pc(vm_state, program_state),
                ..Default::default()
            },
        })
    }
}
