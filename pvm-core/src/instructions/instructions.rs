use crate::{
    constants::JUMP_ALIGNMENT,
    instructions::program_decoder::Instruction,
    state::memory::MemAddress,
    types::{
        common::ExitReason,
        error::{PVMError, VMCoreError},
        hostcall::HostCallType,
    },
    utils::vm_utils::VMUtils,
    vm_core::{PVMCore, Program, SingleInvocationResult, StateChange, VMState},
};
use jam_codec::{JamDecodeFixed, JamEncodeFixed};

pub struct InstructionSet;

impl InstructionSet {
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
    pub fn branch(
        vm_state: &VMState,
        program: &Program,
        target: MemAddress,
        condition: bool,
    ) -> Result<(ExitReason, MemAddress), PVMError> {
        match (condition, program.basic_block_bitmask.get(target as usize)) {
            (false, _) => Ok((ExitReason::Continue, vm_state.pc)),
            (true, Some(true)) => Ok((ExitReason::Continue, target)),
            (true, _) => Ok((ExitReason::Panic, vm_state.pc)),
        }
    }

    /// Performs a dynamic jump operation.
    ///
    /// This function handles jumps where the next instruction is dynamically computed.
    /// The jump address is derived from the jump table, with special handling for alignment
    /// and validity checks.
    pub fn djump(
        vm_state: &VMState,
        program: &Program,
        a: usize,
    ) -> Result<(ExitReason, MemAddress), PVMError> {
        const SPECIAL_HALT_VALUE: usize = (1 << 32) - (1 << 16);

        if a == SPECIAL_HALT_VALUE {
            return Ok((ExitReason::RegularHalt, vm_state.pc));
        }

        let jump_table_len = program.jump_table.len();

        // Check if 'a' is valid and compute the target
        match (a != 0 && a <= jump_table_len * JUMP_ALIGNMENT && a % JUMP_ALIGNMENT == 0)
            .then(|| program.jump_table[(a / JUMP_ALIGNMENT) - 1])
            .filter(|&target| program.basic_block_bitmask[target as usize])
        {
            Some(target) => Ok((ExitReason::Continue, target)),
            None => Ok((ExitReason::Panic, vm_state.pc)),
        }
    }

    //
    // Group 1: Instructions without Arguments
    //

    /// `panic` with no mutation to the VM state
    ///
    /// Opcode: 0
    pub fn trap(vm_state: &VMState, program: &Program) -> Result<SingleInvocationResult, PVMError> {
        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Panic,
            state_change: StateChange {
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Continue program with no mutation to the VM state
    ///
    /// Opcode: 17
    pub fn fallthrough(
        vm_state: &VMState,
        program: &Program,
    ) -> Result<SingleInvocationResult, PVMError> {
        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 2: Instructions with Arguments of One Immediate
    //

    /// Invoke host function call
    ///
    /// Opcode: 78
    pub fn ecalli(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_host_call_type =
            u8::try_from(ins.imm1.unwrap()).map_err(|_| VMCoreError::InvalidImmediateValue)?;

        let exit_reason = HostCallType::from_u8(imm_host_call_type)
            .ok_or(VMCoreError::InvalidHostCallType)
            .map(ExitReason::HostCall)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 3: Instructions with Arguments of Two Immediates
    //

    /// Store immediate argument value to the memory as `u8` integer type
    ///
    /// Opcode: 62
    pub fn store_imm_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = vec![(imm_value & 0xFF) as u8]; // mod 2^8

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 1, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store immediate argument value to the memory as `u16` integer type
    ///
    /// Opcode: 79
    pub fn store_imm_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = ((imm_value & 0xFFFF) as u16).encode_fixed(2)?; // mod 2^16

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 2, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store immediate argument value to the memory as `u32` integer type
    ///
    /// Opcode: 38
    pub fn store_imm_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let imm_value = ins.imm2.unwrap();

        let value = imm_value.encode_fixed(4)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 4, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 4: Instructions with Arguments of One Offset
    //

    /// Jump to the target address with no condition checks
    ///
    /// Opcode: 5
    pub fn jump(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let (exit_reason, target) = Self::branch(vm_state, program, ins.imm1.unwrap(), true)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
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
    pub fn jump_ind(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let r1_val = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let (exit_reason, target) = Self::djump(
            vm_state,
            program,
            ((r1_val as u64 + ins.imm1.unwrap() as u64) % (1 << 32)) as usize,
        )?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Load an immediate value into a register
    ///
    /// Opcode: 4
    pub fn load_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load an unsigned 8-bit value from memory into a register
    ///
    /// Opcode: 60
    pub fn load_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = vm_state.memory.read_byte(imm1)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), val as u32)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load signed 8-bit value from memory into register
    ///
    /// Opcode: 74
    pub fn load_i8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = vm_state.memory.read_byte(imm1)?;
        let signed_val = VMUtils::unsigned_to_signed(1, val as u32).unwrap();
        let unsigned_val = VMUtils::signed_to_unsigned(4, signed_val).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_val)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load unsigned 16-bit value from memory into register
    ///
    /// Opcode: 76
    pub fn load_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = vm_state.memory.read_bytes(imm1, 2)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), u32::decode_fixed(&mut &val[..], 2)?)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load signed 16-bit value from memory into register
    ///
    /// Opcode: 66
    pub fn load_i16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = vm_state.memory.read_bytes(imm1, 2)?;
        let signed_val =
            VMUtils::unsigned_to_signed(2, u32::decode_fixed(&mut &val[..], 2).unwrap()).unwrap();
        let unsigned_val = VMUtils::signed_to_unsigned(4, signed_val).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_val)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load unsigned 32-bit value from memory into register
    ///
    /// Opcode: 10
    pub fn load_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm1 = ins.imm1.unwrap() as MemAddress;
        let val = vm_state.memory.read_bytes(imm1, 4)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(
                    ins.r1.unwrap(),
                    u32::decode_fixed(&mut &val[..], 4).unwrap(),
                )],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store register value to the memory as 8-bit unsigned integer
    ///
    /// Opcode: 71
    pub fn store_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = vec![(ins.r1.unwrap() & 0xFF) as u8];

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 1, r1_value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store register value to memory as 16-bit unsigned integer
    ///
    /// Opcode: 69
    pub fn store_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = (PVMCore::read_reg(vm_state, ins.r1.unwrap())? & 0xFFFF) as u16;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 2, r1_value.encode_fixed(2).unwrap()),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store register value to memory as 32-bit unsigned integer
    ///
    /// Opcode: 22
    pub fn store_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let imm_address = ins.imm1.unwrap() as MemAddress;
        let r1_value = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (imm_address, 4, r1_value.encode_fixed(4).unwrap()),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    // TODO: apply `wrapping_add` to other memory index operation as well
    //
    // Group 6: Instructions with Arguments of One Register & Two Immediates
    //

    /// Store immediate 8-bit value to memory indirectly
    ///
    /// Opcode: 26
    pub fn store_imm_ind_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r1.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vec![(ins.imm2.unwrap() & 0xFF) as u8];

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 1, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store immediate 16-bit value to memory indirectly
    ///
    /// Opcode: 54
    pub fn store_imm_ind_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r1.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = ((ins.imm2.unwrap() & 0xFFFF) as u16).encode_fixed(2)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 2, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store immediate 32-bit value to memory indirectly
    ///
    /// Opcode: 13
    pub fn store_imm_ind_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r1.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = ins.imm2.unwrap().encode_fixed(4)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 4, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 7: Instructions with Arguments of One Register, One Immediate and One Offset
    //

    /// Load immediate value and jump
    ///
    /// Opcode: 6
    pub fn load_imm_jump(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, true)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if equal to immediate
    ///
    /// Opcode: 7
    pub fn branch_eq_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? == ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if not equal to immediate
    ///
    /// Opcode: 15
    pub fn branch_ne_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? != ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than immediate (unsigned)
    ///
    /// Opcode: 44
    pub fn branch_lt_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? < ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than or equal to immediate (unsigned)
    ///
    /// Opcode: 59
    pub fn branch_le_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? <= ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal to immediate (unsigned)
    ///
    /// Opcode: 52
    pub fn branch_ge_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? >= ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than immediate (unsigned)
    ///
    /// Opcode: 50
    pub fn branch_gt_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let condition = PVMCore::read_reg(vm_state, ins.r1.unwrap())? > ins.imm1.unwrap();
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than immediate (signed)
    ///
    /// Opcode: 32
    pub fn branch_lt_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let r1_val =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val < imm_val;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than or equal to immediate (signed)
    ///
    /// Opcode: 46
    pub fn branch_le_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let r1_val =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val <= imm_val;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal to immediate (signed)
    ///
    /// Opcode: 45
    pub fn branch_ge_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let r1_val =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val >= imm_val;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than immediate (signed)
    ///
    /// Opcode: 53
    pub fn branch_gt_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let r1_val =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let imm_val = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let condition = r1_val > imm_val;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    //
    // Group 8: Instructions with Arguments of Two Registers
    //

    /// Move value from one register to another
    ///
    /// Opcode: 82
    pub fn move_reg(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let value = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), value)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// System break (allocate memory)
    ///
    /// This instruction directly mutates the VM memory state unlike other instructions
    ///
    /// Opcode: 87
    pub fn sbrk(
        vm_state: &mut VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let requested_size = PVMCore::read_reg(vm_state, ins.r1.unwrap())? as usize;

        // find the first sequence of unavailable memory cells that can satisfy the request
        let alloc_start = vm_state.memory.get_break(requested_size)?;

        // try expanding the heap area
        vm_state.memory.expand_heap(alloc_start, requested_size)?;

        // returns the start of the newly allocated heap memory
        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), alloc_start)],
                new_pc: Some(PVMCore::next_pc(&vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 9: Instructions with Arguments of Two Registers & One Immediate
    //

    /// Store 8-bit value to memory indirectly
    ///
    /// Opcode: 16
    pub fn store_ind_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vec![(PVMCore::read_reg(vm_state, ins.r1.unwrap())? & 0xFF) as u8];

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 1, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store 16-bit value to memory indirectly
    ///
    /// Opcode: 29
    pub fn store_ind_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value =
            ((PVMCore::read_reg(vm_state, ins.r1.unwrap())? & 0xFFFF) as u16).encode_fixed(2)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 2, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Store 32-bit value to memory indirectly
    ///
    /// Opcode: 3
    pub fn store_ind_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = PVMCore::read_reg(vm_state, ins.r1.unwrap())?.encode_fixed(4)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                memory_write: (address, 4, value),
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load 8-bit unsigned value from memory indirectly
    ///
    /// Opcode: 11
    pub fn load_ind_u8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vm_state.memory.read_byte(address)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), value as u32)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load 8-bit signed value from memory indirectly
    ///
    /// Opcode: 21
    pub fn load_ind_i8(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vm_state.memory.read_byte(address)?;
        let signed_value = VMUtils::unsigned_to_signed(1, value as u32).unwrap();
        let unsigned_value = VMUtils::signed_to_unsigned(4, signed_value).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_value)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load 16-bit unsigned value from memory indirectly
    ///
    /// Opcode: 37
    pub fn load_ind_u16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vm_state.memory.read_bytes(address, 2)?;
        let r_val = u16::decode_fixed(&mut &value[..], 2)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), r_val as u32)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load 16-bit signed value from memory indirectly
    ///
    /// Opcode: 33
    pub fn load_ind_i16(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vm_state.memory.read_bytes(address, 2)?;
        let value_decoded = u16::decode_fixed(&mut &value[..], 2)?;
        let signed_value = VMUtils::unsigned_to_signed(2, value_decoded as u32).unwrap();
        let unsigned_value = VMUtils::signed_to_unsigned(4, signed_value).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_value)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Load 32-bit unsigned value from memory indirectly
    ///
    /// Opcode: 1
    pub fn load_ind_u32(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let address = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());
        let value = vm_state.memory.read_bytes(address, 4)?;
        let value_decoded = u32::decode_fixed(&mut &value[..], 4)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), value_decoded)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Add immediate to register
    ///
    /// Opcode: 2
    pub fn add_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm1.unwrap());

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise AND with immediate
    ///
    /// Opcode: 18
    pub fn and_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & ins.imm1.unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise XOR with immediate
    ///
    /// Opcode: 31
    pub fn xor_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())? ^ ins.imm1.unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise OR with immediate
    ///
    /// Opcode: 49
    pub fn or_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())? | ins.imm1.unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply with immediate
    ///
    /// Opcode: 35
    pub fn mul_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_mul(ins.imm1.unwrap());

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (signed * signed) with immediate
    ///
    /// Opcode: 65
    pub fn mul_upper_s_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?)
            .unwrap() as i64;
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap() as i64;
        let result = ((a * b) >> 32) as i32; // implicitly conducts floor operation
        let unsigned_result = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (unsigned * unsigned) with immediate
    ///
    /// Opcode: 63
    pub fn mul_upper_u_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r2.unwrap())? as u64;
        let b = ins.imm1.unwrap() as u64;
        let result = ((a * b) >> 32) as u32; // implicitly conducts floor operation

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if less than immediate (unsigned)
    ///
    /// Opcode: 27
    pub fn set_lt_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let b = ins.imm1.unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if less than immediate (signed)
    ///
    /// Opcode: 56
    pub fn set_lt_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift left logical with immediate
    ///
    /// Opcode: 9
    pub fn shlo_l_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())? << shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right logical with immediate
    ///
    /// Opcode: 14
    pub fn shlo_r_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let result = PVMCore::read_reg(vm_state, ins.r2.unwrap())? >> shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic with immediate
    ///
    /// Opcode: 25
    pub fn shar_r_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = ins.imm1.unwrap() & 0x1F; // shift range within [0, 32)
        let value =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let result = value >> shift;
        let unsigned_result = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), unsigned_result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Negate and add immediate
    ///
    /// Opcode: 40
    pub fn neg_add_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = ins
            .imm1
            .unwrap()
            .wrapping_sub(PVMCore::read_reg(vm_state, ins.r2.unwrap())?);

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if greater than immediate (unsigned)
    ///
    /// Opcode: 39
    pub fn set_gt_u_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let b = ins.imm1.unwrap();
        let result = if a > b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if greater than immediate (signed)
    ///
    /// Opcode: 61
    pub fn set_gt_s_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let b = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = if a > b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift left logical immediate (alternative)
    ///
    /// Opcode: 75
    pub fn shlo_l_imm_alt(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = ins.imm1.unwrap() << shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right logical immediate (alternative)
    ///
    /// Opcode: 72
    pub fn shlo_r_imm_alt(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = ins.imm1.unwrap() >> shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic immediate (alternative)
    ///
    /// Opcode: 80
    pub fn shar_r_imm_alt(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let value = VMUtils::unsigned_to_signed(4, ins.imm1.unwrap()).unwrap();
        let result = value >> shift;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result_unsigned)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Conditional move if zero with immediate
    ///
    /// Opcode: 85
    pub fn cmov_iz_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = if PVMCore::read_reg(vm_state, ins.r2.unwrap())? == 0 {
            ins.imm1.unwrap()
        } else {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Conditional move if not zero with immediate
    ///
    /// Opcode: 86
    pub fn cmov_nz_imm(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = if PVMCore::read_reg(vm_state, ins.r2.unwrap())? != 0 {
            ins.imm1.unwrap()
        } else {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    //
    // Group 10: Instructions with Arguments of Two Registers & One Offset
    //

    /// Branch if equal
    ///
    /// Opcode: 24
    pub fn branch_eq(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let condition = a == b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if not equal
    ///
    /// Opcode: 30
    pub fn branch_ne(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let condition = a != b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than (unsigned)
    ///
    /// Opcode: 47
    pub fn branch_lt_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let condition = a < b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if less than (signed)
    ///
    /// Opcode: 48
    pub fn branch_lt_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let b =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let condition = a < b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal (unsigned)
    ///
    /// Opcode: 41
    pub fn branch_ge_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let condition = a >= b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    /// Branch if greater than or equal (signed)
    ///
    /// Opcode: 43
    pub fn branch_ge_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let b =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let condition = a >= b;
        let (exit_reason, target) =
            Self::branch(vm_state, program, ins.offset.unwrap() as u32, condition)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    //
    // Group 11: Instructions with Arguments of Two Registers & Two Immediates
    //

    /// Load immediate and jump indirect
    ///
    /// Opcode: 42
    pub fn load_imm_jump_ind(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let jump_address =
            PVMCore::read_reg(vm_state, ins.r2.unwrap())?.wrapping_add(ins.imm2.unwrap());
        let (exit_reason, target) = Self::djump(vm_state, program, jump_address as usize)?;

        Ok(SingleInvocationResult {
            exit_reason,
            state_change: StateChange {
                register_writes: vec![(ins.r1.unwrap(), ins.imm1.unwrap())],
                new_pc: Some(target),
                ..Default::default()
            },
        })
    }

    //
    // Group 12: Instructions with Arguments of Three Registers
    //

    /// Add two registers
    ///
    /// Opcode: 8
    pub fn add(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            .wrapping_add(PVMCore::read_reg(vm_state, ins.r2.unwrap())?);

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Subtract two registers
    ///
    /// Opcode: 20
    pub fn sub(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            .wrapping_sub(PVMCore::read_reg(vm_state, ins.r2.unwrap())?);

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise AND of two registers
    ///
    /// Opcode: 23
    pub fn and(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            & PVMCore::read_reg(vm_state, ins.r2.unwrap())?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise XOR of two registers
    ///
    /// Opcode: 28
    pub fn xor(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            ^ PVMCore::read_reg(vm_state, ins.r2.unwrap())?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Bitwise OR of two registers
    ///
    /// Opcode: 12
    pub fn or(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            | PVMCore::read_reg(vm_state, ins.r2.unwrap())?;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply two registers
    ///
    /// Opcode: 34
    pub fn mul(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())?
            .wrapping_mul(PVMCore::read_reg(vm_state, ins.r2.unwrap())?);

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (signed * signed)
    ///
    /// Opcode: 67
    pub fn mul_upper_s_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?)
            .unwrap() as i64;
        let b = VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?)
            .unwrap() as i64;
        let result = ((a * b) >> 32) as i32;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result_unsigned)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (unsigned * unsigned)
    ///
    /// Opcode: 57
    pub fn mul_upper_u_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())? as u64;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())? as u64;
        let result = ((a * b) >> 32) as u32;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Multiply upper (signed * unsigned)
    ///
    /// Opcode: 81
    pub fn mul_upper_s_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?)
            .unwrap() as i64;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())? as u64;
        let result = ((a * b as i64) >> 32) as i32;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result_unsigned)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Divide unsigned
    ///
    /// Opcode: 68
    pub fn div_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let dividend = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let divisor = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let result = if divisor == 0 {
            u32::MAX
        } else {
            dividend.wrapping_div(divisor)
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Divide signed
    ///
    /// Opcode: 64
    pub fn div_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let dividend =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let divisor =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let result = if divisor == 0 {
            u32::MAX
        } else if dividend == i32::MIN && divisor == -1 {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        } else {
            VMUtils::signed_to_unsigned(4, dividend.wrapping_div(divisor)).unwrap()
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Remainder unsigned
    ///
    /// Opcode: 73
    pub fn rem_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let dividend = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let divisor = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let result = if divisor == 0 {
            dividend
        } else {
            dividend % divisor
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Remainder signed
    ///
    /// Opcode: 70
    pub fn rem_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let dividend =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let divisor =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let result = if divisor == 0 {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        } else if dividend == i32::MIN && divisor == -1 {
            0
        } else {
            VMUtils::signed_to_unsigned(4, dividend % divisor).unwrap()
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if less than (unsigned)
    ///
    /// Opcode: 36
    pub fn set_lt_u(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a = PVMCore::read_reg(vm_state, ins.r1.unwrap())?;
        let b = PVMCore::read_reg(vm_state, ins.r2.unwrap())?;
        let result = if a < b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Set if less than (signed)
    ///
    /// Opcode: 58
    pub fn set_lt_s(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let a =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let b =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r2.unwrap())?).unwrap();
        let result = if a < b { 1 } else { 0 };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift left logical
    ///
    /// Opcode: 55
    pub fn shlo_l(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())? << shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right logical
    ///
    /// Opcode: 51
    pub fn shlo_r(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let result = PVMCore::read_reg(vm_state, ins.r1.unwrap())? >> shift;

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Shift right arithmetic
    ///
    /// Opcode: 77
    pub fn shar_r(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let shift = PVMCore::read_reg(vm_state, ins.r2.unwrap())? & 0x1F; // shift range within [0, 32)
        let value =
            VMUtils::unsigned_to_signed(4, PVMCore::read_reg(vm_state, ins.r1.unwrap())?).unwrap();
        let result = value >> shift;
        let result_unsigned = VMUtils::signed_to_unsigned(4, result).unwrap();

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result_unsigned)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Conditional move if zero
    ///
    /// Opcode: 83
    pub fn cmov_iz(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = if PVMCore::read_reg(vm_state, ins.r2.unwrap())? == 0 {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        } else {
            PVMCore::read_reg(vm_state, ins.rd.unwrap())?
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }

    /// Conditional move if not zero
    ///
    /// Opcode: 84
    pub fn cmov_nz(
        vm_state: &VMState,
        program: &Program,
        ins: &Instruction,
    ) -> Result<SingleInvocationResult, PVMError> {
        let result = if PVMCore::read_reg(vm_state, ins.r2.unwrap())? != 0 {
            PVMCore::read_reg(vm_state, ins.r1.unwrap())?
        } else {
            PVMCore::read_reg(vm_state, ins.rd.unwrap())?
        };

        Ok(SingleInvocationResult {
            exit_reason: ExitReason::Continue,
            state_change: StateChange {
                register_writes: vec![(ins.rd.unwrap(), result)],
                new_pc: Some(PVMCore::next_pc(vm_state, program)),
                ..Default::default()
            },
        })
    }
}
