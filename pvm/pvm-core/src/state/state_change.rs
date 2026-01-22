use crate::{
    error::VMCoreError,
    gas::GasCharger,
    state::{
        memory::MemoryError,
        vm_state::{RegIndex, VMState},
    },
    utils::VMUtils,
};
use fr_common::{SignedGas, UnsignedGas};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, INIT_ZONE_SIZE, INST_BASE_GAS_CHARGE, REGISTERS_COUNT},
};

/// Stores small writes inline to avoid heap allocations for <=8 bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum MemWriteData {
    Inline { len: u8, data: [u8; 8] },
    Vec(Vec<u8>),
}

impl MemWriteData {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, data } => &data[..*len as usize],
            Self::Vec(data) => data.as_slice(),
        }
    }
}

impl Default for MemWriteData {
    fn default() -> Self {
        Self::Inline {
            len: 0,
            data: [0u8; 8],
        }
    }
}

impl From<Vec<u8>> for MemWriteData {
    fn from(data: Vec<u8>) -> Self {
        Self::Vec(data)
    }
}

impl<const N: usize> From<[u8; N]> for MemWriteData {
    fn from(data: [u8; N]) -> Self {
        if N <= 8 {
            let mut buf = [0u8; 8];
            buf[..N].copy_from_slice(&data);
            Self::Inline {
                len: N as u8,
                data: buf,
            }
        } else {
            Self::Vec(data.to_vec())
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemWrite {
    pub buf_offset: MemAddress,
    pub write_data: MemWriteData,
}

impl MemWrite {
    pub fn new<T>(buf_offset: MemAddress, write_data: T) -> Self
    where
        T: Into<MemWriteData>,
    {
        Self {
            buf_offset,
            write_data: write_data.into(),
        }
    }
}

/// VM state change set resulting from a single instruction execution.
#[derive(Debug)]
pub struct VMStateChange {
    pub register_write: Option<(RegIndex, RegValue)>,
    pub memory_write: Option<MemWrite>,
    pub new_pc: RegValue,
    pub gas_charge: UnsignedGas,
}

impl Default for VMStateChange {
    fn default() -> Self {
        Self {
            register_write: None,
            memory_write: None,
            new_pc: 0,
            gas_charge: INST_BASE_GAS_CHARGE,
        }
    }
}

/// VM state change set resulting from a single host function execution.
#[derive(Debug, PartialEq)]
pub struct HostCallVMStateChange {
    pub gas_charge: UnsignedGas,
    pub r7_write: Option<RegValue>,
    pub r8_write: Option<RegValue>,
    pub memory_write: Option<MemWrite>,
}

impl Default for HostCallVMStateChange {
    fn default() -> Self {
        Self {
            gas_charge: HOSTCALL_BASE_GAS_CHARGE,
            r7_write: None,
            r8_write: None,
            memory_write: None,
        }
    }
}

pub struct VMStateMutator;
impl VMStateMutator {
    /// Mutate the VM states from the change set produced by single-step instruction execution functions
    ///
    /// # Returns
    ///
    /// The amount of remaining gas allocation after applying the state change.
    /// This might be negative, which will trigger the out-of-gas exit reason of the general invocation.
    pub fn apply_state_change(
        vm_state: &mut VMState,
        change: &VMStateChange,
        vm_state_should_change: bool,
    ) -> Result<SignedGas, VMCoreError> {
        // Check gas counter and apply gas change
        let post_gas = GasCharger::apply_gas_cost(vm_state, change.gas_charge)?;

        // Early return on OOG or unknown exit reasons without modification in PVM state
        if post_gas < 0 || !vm_state_should_change {
            return Ok(post_gas);
        }

        // Apply memory change first.
        // If this results in Panic or PageFault, VM state should remain unchanged except the gas counter.
        if let Some(MemWrite {
            buf_offset,
            write_data,
        }) = &change.memory_write
        {
            if *buf_offset < INIT_ZONE_SIZE as MemAddress {
                return Err(VMCoreError::ForbiddenMemZone(*buf_offset));
            }

            match vm_state
                .memory
                .write_bytes(*buf_offset, write_data.as_slice())
            {
                Ok(_) => {}
                Err(MemoryError::AccessViolation(address)) => {
                    return Err(VMCoreError::PageFault(VMUtils::page_start_address(address)))
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Apply PC change
        vm_state.pc = change.new_pc;

        // Apply register changes
        if let Some((reg_index, new_val)) = change.register_write {
            if reg_index >= REGISTERS_COUNT {
                return Err(VMCoreError::InvalidRegIndex(reg_index));
            }
            vm_state.regs[reg_index] = new_val;
        }

        Ok(post_gas)
    }

    pub fn apply_host_call_state_change(
        vm_state: &mut VMState,
        change: &HostCallVMStateChange,
    ) -> Result<SignedGas, VMCoreError> {
        // Apply register changes (register index 7 & 8)
        if let Some(r7) = change.r7_write {
            vm_state.regs[7] = r7;
        }
        if let Some(r8) = change.r8_write {
            vm_state.regs[8] = r8;
        }

        // Apply memory change
        if let Some(mem_write) = change.memory_write.as_ref() {
            vm_state
                .memory
                .write_bytes(mem_write.buf_offset, mem_write.write_data.as_slice())?;
        }

        // Check gas counter and apply gas change
        let post_gas = GasCharger::apply_gas_cost(vm_state, change.gas_charge)?;
        Ok(post_gas)
    }
}
