use crate::host_functions::{
    general::GeneralHostFunction, test_utils::mock_empty_vm_state, HostCallResult,
};
use fr_common::SignedGas;
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::RegValue, constants::HOSTCALL_BASE_GAS_CHARGE, exit_reason::ExitReason,
};
use std::error::Error;

mod gas_tests {
    use super::*;
    use crate::host_functions::test_utils::MockStateManager;
    #[test]
    fn test_gas_success() -> Result<(), Box<dyn Error>> {
        let init_gas = 100;
        let vm = mock_empty_vm_state(init_gas);
        let expected_remaining_gas = init_gas as RegValue - HOSTCALL_BASE_GAS_CHARGE as RegValue;
        let res = GeneralHostFunction::<MockStateManager>::host_gas(&vm)?;
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
    fn test_gas_oog() -> Result<(), Box<dyn Error>> {
        let init_gas = HOSTCALL_BASE_GAS_CHARGE - 1;
        let vm = mock_empty_vm_state(init_gas as SignedGas);
        let res = GeneralHostFunction::<MockStateManager>::host_gas(&vm)?;
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
}

mod lookup_tests {
    use super::*;
    use crate::{
        context::{
            partial_state::AccumulatePartialState, AccumulateHostContext,
            AccumulateHostContextPair, InvocationContext,
        },
        host_functions::test_utils::{mock_memory, mock_vm_state, MockStateManager},
    };
    use fr_common::{Hash32, Octets};
    use fr_pvm_core::state::{register::Register, state_change::MemWrite};
    use fr_pvm_types::{
        common::MemAddress, constants::REGISTERS_COUNT, invoke_args::AccumulateInvokeArgs,
    };
    use fr_state::types::AccountPreimagesEntry;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_lookup_accumulate_host_successful() -> Result<(), Box<dyn Error>> {
        let accumulate_host = 1;
        let curr_timeslot_index = 1;
        let curr_entropy = Hash32::default();
        let read_range = 0..100;
        let write_range = 0..100;
        let mem = mock_memory(read_range, write_range)?;

        let init_gas = 100;
        let init_pc = 0;
        let mut regs = [Register::default(); REGISTERS_COUNT];
        let key_offset = 0;
        let mem_write_offset = 2;
        regs[7].value = accumulate_host as RegValue;
        regs[8].value = key_offset;
        regs[9].value = mem_write_offset;
        regs[10].value = 0;
        regs[11].value = 5;

        let vm = mock_vm_state(init_gas, init_pc, regs, mem);

        let preimages_key = Hash32::default();
        let preimages_data = Octets::from_vec(vec![0, 0, 0]);
        let preimages_len = preimages_data.len();

        let state_provider = MockStateManager::default();
        let state_provider = state_provider
            .with_empty_account(accumulate_host)
            .with_preimages_entry(
                accumulate_host,
                preimages_key,
                AccountPreimagesEntry::new(preimages_data.clone()),
            );
        let state_provider = Arc::new(state_provider);

        let partial_state = AccumulatePartialState::default();
        let accumulate_context = AccumulateHostContext::new(
            state_provider.clone(),
            partial_state,
            accumulate_host,
            curr_entropy,
            curr_timeslot_index,
            AccumulateInvokeArgs::default(),
        )
        .await?;
        let mut context = InvocationContext::X_A(AccumulateHostContextPair {
            x: Box::new(accumulate_context.clone()),
            y: Box::new(accumulate_context),
        });

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;

        let expected = HostCallResult {
            exit_reason: ExitReason::Continue,
            vm_change: HostCallVMStateChange {
                gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                r7_write: Some(preimages_len as RegValue),
                r8_write: None,
                memory_write: Some(MemWrite {
                    buf_offset: mem_write_offset as MemAddress,
                    write_data: preimages_data.to_vec(),
                }),
            },
        };
        assert_eq!(res, expected);
        Ok(())
    }

    #[test]
    fn test_lookup_other_account_successful() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }

    #[test]
    fn test_lookup_account_not_found() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }

    #[test]
    fn test_lookup_mem_not_readable() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }

    #[test]
    fn test_lookup_key_not_found_from_partial_state() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }

    #[test]
    fn test_lookup_mem_not_writable() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
