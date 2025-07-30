use crate::host_functions::{
    general::GeneralHostFunction,
    test_utils::{mock_accumulate_host_context, mock_empty_vm_state, mock_memory, mock_vm_state},
    HostCallResult,
};
use fr_common::SignedGas;
use fr_pvm_core::state::{register::Register, state_change::HostCallVMStateChange};
use fr_pvm_types::{
    common::RegValue,
    constants::{HOSTCALL_BASE_GAS_CHARGE, REGISTERS_COUNT},
    exit_reason::ExitReason,
};
use std::error::Error;
// --- GAS

#[test]
fn test_host_gas_success() -> Result<(), Box<dyn Error>> {
    let init_gas = 100;
    let vm = mock_empty_vm_state(init_gas);
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
    let vm = mock_empty_vm_state(init_gas as SignedGas);
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

// --- LOOKUP

#[allow(dead_code)]
fn test_lookup_accumulate_host() -> Result<(), Box<dyn Error>> {
    let accumulate_host = 1;
    let read_range = 0..10;
    let write_range = 0..10;
    let mem = mock_memory(read_range, write_range)?;

    let _context = mock_accumulate_host_context(accumulate_host);

    let init_gas = 100;
    let init_pc = 0;
    let mut regs = [Register::default(); REGISTERS_COUNT];
    regs[7].value = accumulate_host as RegValue;

    let _vm = mock_vm_state(init_gas, init_pc, regs, mem);
    unimplemented!()
}
