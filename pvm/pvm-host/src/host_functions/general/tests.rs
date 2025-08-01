use crate::host_functions::{
    general::GeneralHostFunction,
    test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
    HostCallResult,
};
use fr_common::{ByteEncodable, EntropyHash, Hash32, Octets, SignedGas};
use fr_pvm_core::state::state_change::{HostCallVMStateChange, MemWrite};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::HOSTCALL_BASE_GAS_CHARGE,
    exit_reason::ExitReason,
};
use fr_state::types::AccountPreimagesEntry;
use std::{error::Error, sync::Arc};

mod gas_tests {
    use super::*;

    #[test]
    fn test_gas_success() -> Result<(), Box<dyn Error>> {
        let init_gas = 100;
        let vm = VMStateBuilder::builder().with_gas_counter(init_gas).build();
        let res = GeneralHostFunction::<MockStateManager>::host_gas(&vm)?;
        let expected_remaining_gas = init_gas as RegValue - HOSTCALL_BASE_GAS_CHARGE as RegValue;
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
        let init_gas = (HOSTCALL_BASE_GAS_CHARGE - 1) as SignedGas;
        let vm = VMStateBuilder::builder().with_gas_counter(init_gas).build();
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

    #[tokio::test]
    async fn test_lookup_accumulate_host_successful() -> Result<(), Box<dyn Error>> {
        let accumulate_host = 1;
        let curr_timeslot_index = 1;
        let curr_entropy = EntropyHash::default();

        let key_offset = 0u64;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 0u64;
        let preimage_read_size = 5u64;

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, accumulate_host)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset)
            .with_reg(11, preimage_read_size)
            .with_mem_readable_range(0..100)?
            .with_mem_writable_range(0..100)?
            .build();

        let preimages_key = Hash32::from_hex("0x123")?;
        let preimages_data = vec![0, 0, 0];
        let preimages_len = preimages_data.len();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(accumulate_host)
                .with_preimages_entry(
                    accumulate_host,
                    preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context = InvocationContextBuilder::accumulate_context_builder(
            state_provider.clone(),
            accumulate_host,
            curr_entropy,
            curr_timeslot_index,
        )
        .await?
        .build();

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
                    write_data: preimages_data,
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
