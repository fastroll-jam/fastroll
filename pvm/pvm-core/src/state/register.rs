use crate::error::VMCoreError;
use fr_common::ServiceId;
use fr_pvm_types::common::{MemAddress, RegValue};
use std::fmt::{Debug, Formatter};

#[derive(Clone, Copy, Default, PartialEq)]
pub struct Register {
    pub value: RegValue,
}

impl Debug for Register {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.value)
    }
}

impl Register {
    pub fn new(value: RegValue) -> Self {
        Self { value }
    }

    pub fn value(&self) -> RegValue {
        self.value
    }

    pub fn as_u8(&self) -> Result<u8, VMCoreError> {
        u8::try_from(self.value).map_err(|_| VMCoreError::InvalidRegVal)
    }

    pub fn as_usize(&self) -> Result<usize, VMCoreError> {
        usize::try_from(self.value).map_err(|_| VMCoreError::InvalidRegVal)
    }

    pub fn as_reg_index(&self) -> Result<usize, VMCoreError> {
        self.as_usize()
    }

    pub fn as_u32(&self) -> Result<u32, VMCoreError> {
        u32::try_from(self.value).map_err(|_| VMCoreError::InvalidRegVal)
    }

    #[allow(clippy::useless_conversion)]
    pub fn as_u64(&self) -> Result<u64, VMCoreError> {
        u64::try_from(self.value).map_err(|_| VMCoreError::InvalidRegVal)
    }

    pub fn as_mem_address(&self) -> Result<MemAddress, VMCoreError> {
        self.as_u32()
    }

    pub fn as_service_id(&self) -> Result<ServiceId, VMCoreError> {
        self.as_u32()
    }
}
