use crate::{
    error::{PVMError, VMCoreError::InvalidRegIndex},
    gas::GasCharger,
    state::{memory::MemoryError, register::Register, vm_state::VMState},
};
use rjam_common::{SignedGas, UnsignedGas};
use rjam_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, INIT_ZONE_SIZE, REGISTERS_COUNT},
};

#[derive(Clone, Debug, Default)]
pub struct MemWrite {
    pub buf_offset: MemAddress,
    pub write_data: Vec<u8>,
}

impl MemWrite {
    pub fn new(buf_offset: MemAddress, write_data: Vec<u8>) -> Self {
        Self {
            buf_offset,
            write_data,
        }
    }
}

/// VM state change set resulting from a single instruction execution.
#[derive(Debug, Default)]
pub struct VMStateChange {
    pub register_write: Option<(usize, RegValue)>,
    pub memory_write: Option<MemWrite>,
    pub new_pc: RegValue,
    pub gas_charge: UnsignedGas,
}

/// VM state change set resulting from a single host function execution.
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
    ) -> Result<SignedGas, PVMError> {
        // Apply register changes
        if let Some((reg_index, new_val)) = change.register_write {
            if reg_index >= REGISTERS_COUNT {
                return Err(PVMError::VMCoreError(InvalidRegIndex(reg_index)));
            }
            vm_state.regs[reg_index] = Register::new(new_val);
        }

        // Apply memory change
        if let Some(MemWrite {
            buf_offset,
            write_data,
        }) = &change.memory_write
        {
            if (*buf_offset as usize) < INIT_ZONE_SIZE {
                return Err(PVMError::InvalidMemZone);
            }

            match vm_state.memory.write_bytes(*buf_offset, write_data) {
                Ok(_) => {}
                Err(MemoryError::AccessViolation(address)) => {
                    return Err(PVMError::PageFault(address))
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Apply PC change
        vm_state.pc = change.new_pc;

        // Check gas counter and apply gas change
        let post_gas = GasCharger::apply_gas_cost(vm_state, change.gas_charge)?;
        Ok(post_gas)
    }

    pub fn apply_host_call_state_change(
        vm_state: &mut VMState,
        change: &HostCallVMStateChange,
    ) -> Result<SignedGas, PVMError> {
        // Apply register changes (register index 7 & 8)
        if let Some(r7) = change.r7_write {
            vm_state.regs[7].value = r7;
        }
        if let Some(r8) = change.r8_write {
            vm_state.regs[8].value = r8;
        }

        // Apply memory change
        if let Some(MemWrite {
            buf_offset,
            write_data,
        }) = change.memory_write.clone()
        {
            vm_state.memory.write_bytes(buf_offset, &write_data)?;
        }

        // Check gas counter and apply gas change
        let post_gas = GasCharger::apply_gas_cost(vm_state, change.gas_charge)?;
        Ok(post_gas)
    }
}
