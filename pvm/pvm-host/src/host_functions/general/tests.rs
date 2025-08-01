use crate::host_functions::{
    general::GeneralHostFunction,
    test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
    HostCallResult, HostCallReturnCode,
};
use fr_common::{
    utils::tracing::setup_tracing, ByteEncodable, Hash32, Octets, ServiceId, SignedGas,
};
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
        setup_tracing();
        let accumulate_host = 1;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;
        let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let preimages_len = preimages_data.len();

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, accumulate_host)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .with_mem_writable_range(0..100)?
            .build();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(accumulate_host)
                .with_preimages_entry(
                    accumulate_host,
                    preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
                    write_data: preimages_data
                        [preimage_read_offset..preimage_read_offset + preimage_read_size]
                        .to_vec(),
                }),
            },
        };
        assert_eq!(res, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_other_account_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 1;
        let other_service_id = 2;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;
        let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let preimages_len = preimages_data.len();

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, other_service_id)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .with_mem_writable_range(0..100)?
            .build();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(other_service_id)
                .with_preimages_entry(
                    other_service_id,
                    preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
                    write_data: preimages_data
                        [preimage_read_offset..preimage_read_offset + preimage_read_size]
                        .to_vec(),
                }),
            },
        };
        assert_eq!(res, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_account_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 1;
        let other_service_id = 2 as ServiceId;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, other_service_id)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .with_mem_writable_range(0..100)?
            .build();

        let state_provider = Arc::new(MockStateManager::builder());

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
                r7_write: Some(HostCallReturnCode::NONE as RegValue),
                r8_write: None,
                memory_write: None,
            },
        };
        assert_eq!(res, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 1;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;
        let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, accumulate_host)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .build();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(accumulate_host)
                .with_preimages_entry(
                    accumulate_host,
                    preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
            exit_reason: ExitReason::Panic,
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

    #[tokio::test]
    async fn test_lookup_key_not_found_from_partial_state() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 1;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;
        let another_preimages_key = Hash32::from_hex("0x456")?;
        let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, accumulate_host)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .with_mem_writable_range(0..100)?
            .build();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(accumulate_host)
                .with_preimages_entry(
                    accumulate_host,
                    another_preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
                r7_write: Some(HostCallReturnCode::NONE as RegValue),
                r8_write: None,
                memory_write: None,
            },
        };
        assert_eq!(res, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_mem_not_writable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 1;

        let key_offset = 0u32;
        let mem_write_offset = 2u64;
        let preimage_read_offset = 2usize;
        let preimage_read_size = 5usize;

        let preimages_key = Hash32::from_hex("0x123")?;
        let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let vm = VMStateBuilder::builder()
            .with_pc(0)
            .with_gas_counter(100)
            .with_reg(7, accumulate_host)
            .with_reg(8, key_offset)
            .with_reg(9, mem_write_offset)
            .with_reg(10, preimage_read_offset as RegValue)
            .with_reg(11, preimage_read_size as RegValue)
            .with_mem_data(key_offset, preimages_key.as_slice())?
            .with_mem_readable_range(0..100)?
            .build();

        let state_provider = Arc::new(
            MockStateManager::builder()
                .with_empty_account(accumulate_host)
                .with_preimages_entry(
                    accumulate_host,
                    preimages_key,
                    AccountPreimagesEntry::new(Octets::from_vec(preimages_data.clone())),
                ),
        );

        let mut context =
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider.clone(),
                accumulate_host,
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
            exit_reason: ExitReason::Panic,
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
