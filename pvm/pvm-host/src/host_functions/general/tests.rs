use crate::host_functions::{
    general::GeneralHostFunction, test_utils::create_vm_state, HostCallResult,
};
use fr_common::SignedGas;
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::RegValue, constants::HOSTCALL_BASE_GAS_CHARGE, exit_reason::ExitReason,
};
use std::error::Error;

// --- GAS

#[test]
fn test_host_gas_success() -> Result<(), Box<dyn Error>> {
    let init_gas = 100;
    let vm = create_vm_state(init_gas);
    let expected_remaining_gas = init_gas as RegValue - HOSTCALL_BASE_GAS_CHARGE as RegValue;
    let res = GeneralHostFunction::host_gas(&vm)?;
    let expected = HostCallResult {
        exit_reason: ExitReason::Continue,
        vm_change: HostCallVMStateChange {
            gas_charge: HOSTCALL_BASE_GAS_CHARGE,
            r7_write: Some(expected_remaining_gas),
            r8_write: None,
            memory_write: None,
        },
    };
    assert_eq!(res, expected);
    Ok(())
}

#[test]
fn test_host_gas_oog() -> Result<(), Box<dyn Error>> {
    let init_gas = HOSTCALL_BASE_GAS_CHARGE - 1;
    let vm = create_vm_state(init_gas as SignedGas);
    let res = GeneralHostFunction::host_gas(&vm)?;
    let expected = HostCallResult {
        exit_reason: ExitReason::OutOfGas,
        vm_change: HostCallVMStateChange {
            gas_charge: HOSTCALL_BASE_GAS_CHARGE,
            r7_write: None,
            r8_write: None,
            memory_write: None,
        },
    };
    assert_eq!(res, expected);
    Ok(())
}
