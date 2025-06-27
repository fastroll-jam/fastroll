use crate::{
    error::VMCoreError,
    program::instruction::Instruction,
    state::{memory::Memory, register::Register},
};
use fr_common::SignedGas;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::REGISTERS_COUNT,
};

pub type RegIndex = usize;

/// Mutable VM state
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VMState {
    /// `φ`: Registers
    pub regs: [Register; REGISTERS_COUNT],
    /// `μ`: RAM
    pub memory: Memory,
    /// `ı`: Program counter
    pub pc: RegValue,
    /// `ρ`: Gas counter
    pub gas_counter: SignedGas,
}

impl VMState {
    pub fn pc(&self) -> RegValue {
        self.pc
    }

    pub fn pc_as_mem_address(&self) -> Result<MemAddress, VMCoreError> {
        MemAddress::try_from(self.pc).map_err(|_| VMCoreError::InvalidRegVal)
    }

    pub fn read_reg(&self, index: RegIndex) -> RegValue {
        self.regs[index].value()
    }

    pub fn read_reg_as_mem_address(&self, index: RegIndex) -> Result<MemAddress, VMCoreError> {
        self.regs[index].as_mem_address()
    }

    pub fn read_reg_as_reg_index(&self, index: RegIndex) -> Result<usize, VMCoreError> {
        self.regs[index].as_reg_index()
    }

    pub fn read_rs1(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        Ok(self.regs[ins.rs1()?].value())
    }

    pub fn read_rs2(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        Ok(self.regs[ins.rs2()?].value())
    }

    pub fn read_rd(&self, ins: &Instruction) -> Result<RegValue, VMCoreError> {
        Ok(self.regs[ins.rd()?].value())
    }
}
