use crate::{
    constants::REGISTERS_COUNT,
    program::decoder::Instruction,
    state::{
        memory::{MemAddress, Memory},
        register::Register,
    },
    types::{
        common::RegValue,
        error::{PVMError, VMCoreError::InvalidRegVal},
    },
};
use rjam_common::UnsignedGas;

/// Mutable VM state
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VMState {
    /// `ω`: Registers
    pub regs: [Register; REGISTERS_COUNT],
    /// `μ`: RAM
    pub memory: Memory,
    /// `ı`: Program counter
    pub pc: RegValue,
    /// `ρ`: Gas counter
    pub gas_counter: UnsignedGas,
}

impl VMState {
    pub fn pc(&self) -> RegValue {
        self.pc
    }

    pub fn pc_as_mem_address(&self) -> Result<MemAddress, PVMError> {
        MemAddress::try_from(self.pc).map_err(|_| PVMError::VMCoreError(InvalidRegVal))
    }

    pub fn read_reg(&self, index: usize) -> RegValue {
        self.regs[index].value()
    }

    pub fn read_reg_as_mem_address(&self, index: usize) -> Result<MemAddress, PVMError> {
        self.regs[index].as_mem_address()
    }

    pub fn read_reg_as_reg_index(&self, index: usize) -> Result<usize, PVMError> {
        self.regs[index].as_reg_index()
    }

    pub fn read_rs1(&self, ins: &Instruction) -> Result<RegValue, PVMError> {
        Ok(self.regs[ins.rs1()?].value())
    }

    pub fn read_rs2(&self, ins: &Instruction) -> Result<RegValue, PVMError> {
        Ok(self.regs[ins.rs2()?].value())
    }

    pub fn read_rd(&self, ins: &Instruction) -> Result<RegValue, PVMError> {
        Ok(self.regs[ins.rd()?].value())
    }
}
