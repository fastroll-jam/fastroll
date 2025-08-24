use fr_common::UnsignedGas;
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::RegValue, constants::HOSTCALL_BASE_GAS_CHARGE, exit_reason::ExitReason,
};

pub mod accumulate;
pub mod debug;
pub mod general;
pub mod refine;
#[cfg(test)]
mod test_utils;

#[repr(u64)]
#[derive(Debug)]
pub enum HostCallReturnCode {
    /// An item does not exist.
    NONE = u64::MAX,
    /// Name unknown.
    WHAT = u64::MAX - 1,
    /// The inner PVM memory index provided for reading/writing is not accessible.
    OOB = u64::MAX - 2,
    /// Index unknown.
    WHO = u64::MAX - 3,
    /// Storage full
    FULL = u64::MAX - 4,
    /// Core index unknown.
    CORE = u64::MAX - 5,
    /// Insufficient funds.
    CASH = u64::MAX - 6,
    /// Gas limit too low.
    LOW = u64::MAX - 7,
    /// The item is already solicited or cannot be forgotten.
    HUH = u64::MAX - 8,
    /// The return value indicating general success.
    OK = 0,
}

#[repr(u32)]
pub enum InnerPVMResultConstant {
    /// Normal halt
    HALT = 0,
    /// Panic
    PANIC = 1,
    /// Page fault
    FAULT = 2,
    /// Host-call fault
    HOST = 3,
    /// out of gas
    OOG = 4,
}

#[derive(Default, Debug, PartialEq)]
pub struct HostCallResult {
    pub exit_reason: ExitReason,
    pub vm_change: HostCallVMStateChange,
}

impl HostCallResult {
    fn continue_with_vm_change(vm_change: HostCallVMStateChange) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change,
        }
    }

    pub fn continue_with_return_code(code: HostCallReturnCode) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change: HostCallVMStateChange {
                gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                r7_write: Some(code as RegValue),
                ..Default::default()
            },
        }
    }

    pub fn continue_with_return_code_and_gas(
        code: HostCallReturnCode,
        gas_charge: UnsignedGas,
    ) -> Self {
        Self {
            exit_reason: ExitReason::Continue,
            vm_change: HostCallVMStateChange {
                gas_charge,
                r7_write: Some(code as RegValue),
                ..Default::default()
            },
        }
    }

    pub fn panic() -> Self {
        Self {
            exit_reason: ExitReason::Panic,
            vm_change: Default::default(),
        }
    }

    pub fn panic_with_gas(gas_charge: UnsignedGas) -> Self {
        Self {
            exit_reason: ExitReason::Panic,
            vm_change: HostCallVMStateChange {
                gas_charge,
                ..Default::default()
            },
        }
    }

    pub fn out_of_gas() -> Self {
        Self {
            exit_reason: ExitReason::OutOfGas,
            vm_change: Default::default(),
        }
    }

    pub fn out_of_gas_with_gas(gas_charge: UnsignedGas) -> Self {
        Self {
            exit_reason: ExitReason::OutOfGas,
            vm_change: HostCallVMStateChange {
                gas_charge,
                ..Default::default()
            },
        }
    }
}
