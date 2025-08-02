use crate::{
    context::InvocationContext,
    host_functions::{
        general::GeneralHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
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
use fr_state::types::{AccountPreimagesEntry, AccountStorageEntry};
use std::{error::Error, ops::Range, sync::Arc};

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
    use fr_common::HASH_SIZE;

    struct LookupTestFixture {
        accumulate_host: ServiceId,
        other_service_id: ServiceId,
        preimages_key_mem_offset: MemAddress,
        preimages_read_offset: usize,
        preimages_read_size: usize,
        preimages_key: Hash32,
        preimages_data: Vec<u8>,
        preimages_data_len: usize,
        mem_write_offset: MemAddress,
        mem_readable_range: Range<MemAddress>,
        mem_writable_range: Range<MemAddress>,
    }

    impl Default for LookupTestFixture {
        fn default() -> Self {
            let preimages_key_mem_offset = 10_000;
            let preimages_read_size = 5;
            let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let preimages_data_len = preimages_data.len();
            let mem_write_offset = 2;
            let mem_readable_range = preimages_key_mem_offset as MemAddress
                ..preimages_key_mem_offset as MemAddress + HASH_SIZE as MemAddress;
            let mem_writable_range = mem_write_offset as MemAddress
                ..mem_write_offset as MemAddress + preimages_read_size as MemAddress;
            Self {
                accumulate_host: 1,
                other_service_id: 2,
                preimages_key_mem_offset,
                preimages_read_offset: 2,
                preimages_read_size,
                preimages_key: Hash32::from_hex("0x123").unwrap(),
                preimages_data,
                preimages_data_len,
                mem_write_offset,
                mem_readable_range,
                mem_writable_range,
            }
        }
    }

    impl LookupTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            Ok(VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(8, self.preimages_key_mem_offset)
                .with_reg(9, self.mem_write_offset)
                .with_reg(10, self.preimages_read_offset as RegValue)
                .with_reg(11, self.preimages_read_size as RegValue)
                .with_mem_data(self.preimages_key_mem_offset, self.preimages_key.as_slice())?)
        }

        fn prepare_state_provider(
            &self,
            service_with_preimages_entry: Option<ServiceId>,
        ) -> MockStateManager {
            match service_with_preimages_entry {
                Some(service_id) => MockStateManager::builder()
                    .with_empty_account(service_id)
                    .with_preimages_entry(
                        service_id,
                        self.preimages_key.clone(),
                        AccountPreimagesEntry::new(Octets::from_vec(self.preimages_data.clone())),
                    ),
                None => MockStateManager::default(),
            }
        }

        async fn prepare_invocation_context(
            &self,
            state_provider: Arc<MockStateManager>,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            Ok(
            InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider,
                self.accumulate_host
            )
            .await?.build())
        }

        fn host_call_result_successful(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(self.preimages_data_len as RegValue),
                    r8_write: None,
                    memory_write: Some(MemWrite {
                        buf_offset: self.mem_write_offset as MemAddress,
                        write_data: self.preimages_data[self.preimages_read_offset
                            ..self.preimages_read_offset + self.preimages_read_size]
                            .to_vec(),
                    }),
                },
            }
        }

        fn host_call_result_none() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::NONE as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_panic() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Panic,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: None,
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_lookup_accumulate_host_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.accumulate_host)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();
        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful());
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_other_account_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.other_service_id)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();
        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.other_service_id)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful());
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_account_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.other_service_id)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();
        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, LookupTestFixture::host_call_result_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.accumulate_host)
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();
        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, LookupTestFixture::host_call_result_panic());
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_key_not_found_from_partial_state() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.accumulate_host)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider(None));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, LookupTestFixture::host_call_result_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_mem_not_writable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = LookupTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.accumulate_host)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_lookup(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, LookupTestFixture::host_call_result_panic());
        Ok(())
    }
}

mod read_tests {
    use super::*;

    struct ReadTestFixture {
        accumulate_host: ServiceId,
        other_service_id: ServiceId,
        storage_key_mem_offset: MemAddress,
        storage_key_size: usize,
        storage_read_offset: usize,
        storage_read_size: usize,
        storage_key: Octets,
        storage_data: Vec<u8>,
        storage_data_len: usize,
        mem_write_offset: MemAddress,
        mem_readable_range: Range<MemAddress>,
        mem_writable_range: Range<MemAddress>,
    }

    impl Default for ReadTestFixture {
        fn default() -> Self {
            let storage_key_mem_offset = 10_000;
            let storage_key_size = 3;
            let storage_data = (0..255).collect::<Vec<u8>>();
            let storage_data_len = storage_data.len();
            let storage_read_size = 30;
            let mem_write_offset = 3;
            let mem_readable_range = storage_key_mem_offset as MemAddress
                ..storage_key_mem_offset as MemAddress + storage_key_size as MemAddress;
            let mem_writable_range = mem_write_offset as MemAddress
                ..mem_write_offset as MemAddress + storage_read_size as MemAddress;
            Self {
                accumulate_host: ServiceId::MAX,
                other_service_id: ServiceId::MAX - 1,
                storage_key_mem_offset,
                storage_key_size,
                storage_read_offset: 30,
                storage_read_size,
                storage_key: Octets::from_vec((0..storage_key_size as u8).collect::<Vec<_>>()),
                storage_data,
                storage_data_len,
                mem_write_offset,
                mem_readable_range,
                mem_writable_range,
            }
        }
    }

    impl ReadTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            Ok(VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(8, self.storage_key_mem_offset)
                .with_reg(9, self.storage_key_size as RegValue)
                .with_reg(10, self.mem_write_offset)
                .with_reg(11, self.storage_read_offset as RegValue)
                .with_reg(12, self.storage_read_size as RegValue))
        }

        fn prepare_state_provider(
            &self,
            service_with_storage_entry: Option<ServiceId>,
        ) -> MockStateManager {
            match service_with_storage_entry {
                Some(service_id) => MockStateManager::builder()
                    .with_empty_account(service_id)
                    .with_storage_entry(
                        service_id,
                        self.storage_key.clone(),
                        AccountStorageEntry::new(Octets::from_vec(self.storage_data.clone())),
                    ),
                None => MockStateManager::default(),
            }
        }

        async fn prepare_invocation_context(
            &self,
            state_provider: Arc<MockStateManager>,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            Ok(InvocationContextBuilder::accumulate_context_builder_with_default_entropy_and_timeslot(
                state_provider,
                self.accumulate_host,
            )
                .await?
                .build())
        }

        fn host_call_result_successful(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(self.storage_data_len as RegValue),
                    r8_write: None,
                    memory_write: Some(MemWrite {
                        buf_offset: self.mem_write_offset as MemAddress,
                        write_data: self.storage_data[self.storage_read_offset
                            ..self.storage_read_offset + self.storage_read_size]
                            .to_vec(),
                    }),
                },
            }
        }

        fn host_call_result_none() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::NONE as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_panic() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Panic,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: None,
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_read_accumulate_host_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, u64::MAX)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();

        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful());
        Ok(())
    }

    #[tokio::test]
    async fn test_read_other_account_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, fixture.other_service_id)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();

        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.other_service_id)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful());
        Ok(())
    }

    #[tokio::test]
    async fn test_read_account_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, u64::MAX)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();

        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.other_service_id)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, ReadTestFixture::host_call_result_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_read_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, u64::MAX)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();

        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, ReadTestFixture::host_call_result_panic());
        Ok(())
    }

    #[tokio::test]
    async fn test_read_mem_not_writable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, u64::MAX)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();

        let state_provider =
            Arc::new(fixture.prepare_state_provider(Some(fixture.accumulate_host)));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, ReadTestFixture::host_call_result_panic());
        Ok(())
    }

    #[tokio::test]
    async fn test_read_key_not_found_from_partial_state() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = ReadTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, u64::MAX)
            .with_mem_data(
                fixture.storage_key_mem_offset,
                fixture.storage_key.as_slice(),
            )?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .with_mem_writable_range(fixture.mem_writable_range.clone())?
            .build();

        let state_provider = Arc::new(fixture.prepare_state_provider(None));
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;
        let res = GeneralHostFunction::<MockStateManager>::host_read(
            fixture.accumulate_host,
            &vm,
            state_provider,
            &mut context,
        )
        .await?;
        assert_eq!(res, ReadTestFixture::host_call_result_none());
        Ok(())
    }
}
