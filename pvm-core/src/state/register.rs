use crate::{
    state::memory::MemAddress,
    types::{
        common::RegValue,
        error::{PVMError, VMCoreError::InvalidRegValue},
    },
};
use rjam_common::Address;

#[derive(Clone, Copy, Default)]
pub struct Register {
    pub value: RegValue,
}

impl Register {
    pub fn new(value: RegValue) -> Self {
        Self { value }
    }

    pub fn value(&self) -> RegValue {
        self.value
    }

    pub fn as_u8(&self) -> Result<u8, PVMError> {
        u8::try_from(self.value).map_err(|_| PVMError::VMCoreError(InvalidRegValue))
    }

    pub fn as_usize(&self) -> Result<usize, PVMError> {
        usize::try_from(self.value).map_err(|_| PVMError::VMCoreError(InvalidRegValue))
    }

    pub fn as_reg_index(&self) -> Result<usize, PVMError> {
        self.as_usize()
    }

    pub fn as_u32(&self) -> Result<u32, PVMError> {
        u32::try_from(self.value).map_err(|_| PVMError::VMCoreError(InvalidRegValue))
    }

    pub fn as_mem_address(&self) -> Result<MemAddress, PVMError> {
        self.as_u32()
    }

    pub fn as_account_address(&self) -> Result<Address, PVMError> {
        self.as_u32()
    }
}
