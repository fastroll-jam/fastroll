use crate::{error::VMCoreError, program::instruction::Instruction, state::memory::Memory};
use fr_common::{Balance, ServiceId, SignedGas};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::REGISTERS_COUNT,
};

pub type RegIndex = usize;
pub type Registers = [RegValue; REGISTERS_COUNT];

/// Mutable VM state
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VMState {
    /// `φ`: Registers
    pub regs: Registers,
    /// `μ`: RAM
    pub memory: Memory,
    /// `ı`: Program counter
    pub pc: RegValue,
    /// `ρ`: Gas counter
    pub gas_counter: SignedGas,
}

impl VMState {
    #[inline(always)]
    pub fn pc(&self) -> RegValue {
        self.pc
    }

    #[inline(always)]
    pub fn pc_as_mem_address(&self) -> Result<MemAddress, VMCoreError> {
        MemAddress::try_from(self.pc).map_err(|_| VMCoreError::InvalidPCVal(self.pc))
    }

    #[inline(always)]
    pub fn read_reg(&self, index: RegIndex) -> RegValue {
        self.regs[index]
    }

    #[inline(always)]
    pub fn read_reg_as_usize(&self, index: RegIndex) -> Result<usize, VMCoreError> {
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        usize::try_from(*reg).map_err(|_| VMCoreError::InvalidRegVal(index, *reg))
    }

    #[inline(always)]
    pub fn read_reg_as_service_id(&self, index: RegIndex) -> Result<ServiceId, VMCoreError> {
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        ServiceId::try_from(*reg).map_err(|_| VMCoreError::InvalidRegVal(index, *reg))
    }

    #[inline(always)]
    pub fn read_reg_as_mem_address(&self, index: RegIndex) -> Result<MemAddress, VMCoreError> {
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        MemAddress::try_from(*reg).map_err(|_| VMCoreError::InvalidRegVal(index, *reg))
    }

    #[inline(always)]
    pub fn read_reg_as_u32(&self, index: RegIndex) -> Result<u32, VMCoreError> {
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        u32::try_from(*reg).map_err(|_| VMCoreError::InvalidRegVal(index, *reg))
    }

    #[inline(always)]
    pub fn read_reg_as_balance(&self, index: RegIndex) -> Result<Balance, VMCoreError> {
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        Balance::try_from(*reg).map_err(|_| VMCoreError::InvalidRegVal(index, *reg))
    }

    #[inline(always)]
    pub fn read_rs1(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        let index = ins.rs1()?;
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        Ok(*reg)
    }

    #[inline(always)]
    pub fn read_rs2(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        let index = ins.rs2()?;
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        Ok(*reg)
    }

    #[inline(always)]
    pub fn read_rd(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        let index = ins.rd()?;
        let reg = self
            .regs
            .get(index)
            .ok_or(VMCoreError::InvalidRegIndex(index))?;
        Ok(*reg)
    }
}
