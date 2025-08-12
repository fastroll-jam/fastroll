use crate::{
    context::InvocationContext,
    host_functions::{
        general::GeneralHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
};
use fr_common::{
    utils::tracing::setup_tracing,
    workloads::{RefinementContext, WorkItems, WorkPackage},
    Balance, ByteEncodable, CodeHash, EntropyHash, Octets, PreimagesKey, ServiceId, SignedGas,
    StorageKey, HASH_SIZE,
};
use fr_pvm_core::state::state_change::{HostCallVMStateChange, MemWrite};
use fr_pvm_types::{
    common::{MemAddress, RegValue, WorkPackageImportSegments},
    constants::{HOSTCALL_BASE_GAS_CHARGE, PAGE_SIZE},
    exit_reason::ExitReason,
    invoke_args::AccumulateInputs,
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

#[allow(dead_code)]
mod fetch_tests {
    use super::*;
    use crate::context::{
        partial_state::AccumulatePartialState, AccumulateHostContext, AccumulateHostContextPair,
        IsAuthorizedHostContext, RefineHostContext,
    };
    use fr_common::{
        constants_encoder::encode_constants_for_fetch_hostcall,
        workloads::{WorkExecutionResult, WorkItem},
        AuthHash, BeefyRoot, BlockHeaderHash, Hash32, SegmentRoot, StateRoot, WorkPackageHash,
        SEGMENT_SIZE,
    };
    use fr_pvm_types::{
        common::ExportDataSegment,
        invoke_args::{
            AccumulateInvokeArgs, AccumulateOperand, DeferredTransfer, IsAuthorizedInvokeArgs,
            RefineInvokeArgs, TransferMemo,
        },
    };
    use std::collections::{BTreeSet, HashMap, HashSet};

    struct RegParams {
        mem_write_offset: MemAddress,
        fetch_offset: usize,
        fetch_length: usize,
        data_id: usize,
        index_reg_11: usize,
        index_reg_12: usize,
    }

    impl Default for RegParams {
        fn default() -> Self {
            Self {
                mem_write_offset: PAGE_SIZE as MemAddress,
                fetch_offset: 5,
                fetch_length: 10,
                data_id: 0,
                index_reg_11: 0,
                index_reg_12: 0,
            }
        }
    }

    struct FetchTestFixture {
        regs: RegParams,
        chain_params_encoded: Vec<u8>,
        entropy: EntropyHash,
        auth_trace: Vec<u8>,
        extrinsics: Vec<Vec<Vec<u8>>>,
        imports: WorkPackageImportSegments,
        package: WorkPackage,
        accumulate_inputs: AccumulateInputs,
    }

    impl Default for FetchTestFixture {
        fn default() -> Self {
            let imports_segment = ExportDataSegment::try_from(vec![3; SEGMENT_SIZE]).unwrap();
            let package_auth_code_hash = CodeHash::from_hex("0x2").unwrap();
            let package_config_blob = vec![4; 100];
            let package_auth_token = vec![5; 100];
            let package_refine_context = RefinementContext {
                anchor_header_hash: BlockHeaderHash::from_hex("0x3").unwrap(),
                anchor_state_root: StateRoot::from_hex("0x4").unwrap(),
                anchor_beefy_root: BeefyRoot::from_hex("0x5").unwrap(),
                lookup_anchor_header_hash: BlockHeaderHash::from_hex("0x6").unwrap(),
                lookup_anchor_timeslot: 10,
                prerequisite_work_packages: BTreeSet::new(),
            };
            let work_items_in_package = 3;
            let work_items = WorkItems::try_from(vec![
                WorkItem {
                    service_id: 0,
                    payload_blob: Octets::from_vec(vec![7; 100]),
                    ..Default::default()
                },
                WorkItem {
                    service_id: 1,
                    payload_blob: Octets::from_vec(vec![8; 100]),
                    ..Default::default()
                },
                WorkItem {
                    service_id: 2,
                    payload_blob: Octets::from_vec(vec![9; 100]),
                    ..Default::default()
                },
            ])
            .unwrap();
            let package = WorkPackage {
                authorizer_service_id: ServiceId::MAX,
                auth_code_hash: package_auth_code_hash,
                context: package_refine_context,
                auth_token: Octets::from_vec(package_auth_token),
                config_blob: Octets::from_vec(package_config_blob),
                work_items,
            };

            let deferred_transfers = vec![DeferredTransfer {
                from: 0,
                to: 1,
                amount: 333,
                memo: TransferMemo::from_hex("0xabc").unwrap(),
                gas_limit: 10,
            }];
            let accumulate_operands = vec![AccumulateOperand {
                work_package_hash: WorkPackageHash::from_hex("0x7").unwrap(),
                segment_root: SegmentRoot::default(),
                authorizer_hash: AuthHash::default(),
                work_item_payload_hash: Hash32::default(),
                accumulate_gas_limit: 100,
                refine_result: WorkExecutionResult::Output(Octets::from_vec(vec![])),
                auth_trace: vec![],
            }];
            Self {
                regs: RegParams::default(),
                chain_params_encoded: encode_constants_for_fetch_hostcall().unwrap(),
                entropy: EntropyHash::from_hex("0x1").unwrap(),
                auth_trace: vec![0; 100],
                extrinsics: vec![vec![vec![1; 100]; 64]; work_items_in_package], // 64 extrinsics per work-item / 3 work-items // TODO: distinct xts
                imports: vec![vec![imports_segment; 1024]; work_items_in_package], // 1024 imports per work-item / 3 work-items
                package,
                accumulate_inputs: AccumulateInputs::new(deferred_transfers, accumulate_operands),
            }
        }
    }

    impl FetchTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            Ok(VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.regs.mem_write_offset)
                .with_reg(8, self.regs.fetch_offset as RegValue)
                .with_reg(9, self.regs.fetch_length as RegValue)
                .with_reg(10, self.regs.data_id as RegValue)
                .with_reg(11, self.regs.index_reg_11 as RegValue)
                .with_reg(12, self.regs.index_reg_12 as RegValue))
        }

        fn prepare_is_authorized_invocation_context(
            &self,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            Ok(InvocationContext::X_I(IsAuthorizedHostContext {
                invoke_args: IsAuthorizedInvokeArgs {
                    package: self.package.clone(),
                    core_idx: 1,
                },
            }))
        }

        fn prepare_refine_invocation_context(
            &self,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            Ok(InvocationContext::X_R(RefineHostContext {
                next_instance_id: 0,
                pvm_instances: HashMap::new(),
                export_segments: Vec::new(),
                refine_entropy: self.entropy.clone(),
                invoke_args: RefineInvokeArgs {
                    core_idx: 1,
                    item_idx: 2,
                    package: self.package.clone(),
                    auth_trace: self.auth_trace.clone(),
                    import_segments: self.imports.clone(),
                    export_segments_offset: 0,
                    extrinsic_data_map: HashMap::new(), // TODO: fill data
                },
            }))
        }

        fn prepare_is_accumulate_invocation_context(
            &self,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            let context = AccumulateHostContext {
                accumulate_host: 0,
                partial_state: AccumulatePartialState::default(),
                next_new_service_id: 0,
                deferred_transfers: vec![],
                yielded_accumulate_hash: None,
                provided_preimages: HashSet::new(),
                invoke_args: AccumulateInvokeArgs {
                    inputs: self.accumulate_inputs.clone(),
                    ..Default::default()
                },
                curr_entropy: self.entropy.clone(),
            };
            Ok(InvocationContext::X_A(AccumulateHostContextPair {
                x: Box::new(context.clone()),
                y: Box::new(context),
            }))
        }
    }

    mod is_authorized {
        use super::*;

        #[tokio::test]
        async fn test_fetch_is_authorized_id_0() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_7() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_8() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_9() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_10() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_11() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_12() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_is_authorized_id_13() -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }

    mod refine {
        use super::*;

        #[tokio::test]
        async fn test_fetch_refine_id_0() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_1() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_2() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_3() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_4() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_5() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_6() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_7() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_8() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_9() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_10() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_11() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_12() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_refine_id_13() -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }

    mod accumulate {
        use super::*;

        #[tokio::test]
        async fn test_fetch_accumulate_id_0() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_accumulate_id_1() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_accumulate_id_14() -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        #[tokio::test]
        async fn test_fetch_accumulate_id_15() -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }
}

mod lookup_tests {
    use super::*;

    struct LookupTestFixture {
        accumulate_host: ServiceId,
        other_service_id: ServiceId,
        preimages_key_mem_offset: MemAddress,
        preimages_read_offset: usize,
        preimages_read_size: usize,
        preimages_key: PreimagesKey,
        preimages_data: Vec<u8>,
        preimages_data_len: usize,
        mem_write_offset: MemAddress,
        mem_readable_range: Range<MemAddress>,
        mem_writable_range: Range<MemAddress>,
    }

    impl Default for LookupTestFixture {
        fn default() -> Self {
            let preimages_key_mem_offset = PAGE_SIZE as MemAddress;
            let preimages_read_size = 5;
            let preimages_data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
            let preimages_data_len = preimages_data.len();
            let mem_write_offset = 2 * PAGE_SIZE as MemAddress;
            let mem_readable_range =
                preimages_key_mem_offset..preimages_key_mem_offset + HASH_SIZE as MemAddress;
            let mem_writable_range =
                mem_write_offset..mem_write_offset + preimages_read_size as MemAddress;
            Self {
                accumulate_host: 1,
                other_service_id: 2,
                preimages_key_mem_offset,
                preimages_read_offset: 2,
                preimages_read_size,
                preimages_key: PreimagesKey::from_hex("0x123").unwrap(),
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
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(8, self.preimages_key_mem_offset)
                .with_reg(9, self.mem_write_offset)
                .with_reg(10, self.preimages_read_offset as RegValue)
                .with_reg(11, self.preimages_read_size as RegValue)
                .with_mem_data(self.preimages_key_mem_offset, self.preimages_key.as_slice())
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
                InvocationContextBuilder::accumulate_context_builder_default(
                    state_provider,
                    self.accumulate_host,
                )
                .await?
                .build(),
            )
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
        storage_key: StorageKey,
        storage_data: Vec<u8>,
        storage_data_len: usize,
        mem_write_offset: MemAddress,
        mem_readable_range: Range<MemAddress>,
        mem_writable_range: Range<MemAddress>,
    }

    impl Default for ReadTestFixture {
        fn default() -> Self {
            let storage_key_mem_offset = 3 * PAGE_SIZE as MemAddress;
            let storage_key_size = 3;
            let storage_data = (0..255).collect::<Vec<u8>>();
            let storage_data_len = storage_data.len();
            let storage_read_size = 30;
            let mem_write_offset = 10 * PAGE_SIZE as MemAddress;
            let mem_readable_range =
                storage_key_mem_offset..storage_key_mem_offset + storage_key_size as MemAddress;
            let mem_writable_range =
                mem_write_offset..mem_write_offset + storage_read_size as MemAddress;
            Self {
                accumulate_host: ServiceId::MAX,
                other_service_id: ServiceId::MAX - 1,
                storage_key_mem_offset,
                storage_key_size,
                storage_read_offset: 30,
                storage_read_size,
                storage_key: StorageKey::from_vec((0..storage_key_size as u8).collect::<Vec<_>>()),
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
            Ok(
                InvocationContextBuilder::accumulate_context_builder_default(
                    state_provider,
                    self.accumulate_host,
                )
                .await?
                .build(),
            )
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

mod write_tests {
    use super::*;

    struct WriteTestFixture {
        accumulate_host: ServiceId,
        accumulate_host_balance: Balance,
        storage_key_mem_offset: MemAddress,
        storage_key_size: usize,
        storage_data_mem_offset: MemAddress,
        storage_data_size: usize,
        storage_key: StorageKey,
        storage_data: Vec<u8>,
        prev_storage_data: Option<Vec<u8>>,
        prev_storage_data_size: usize,
        mem_readable_range_for_key: Range<MemAddress>,
        mem_readable_range_for_data: Range<MemAddress>,
    }

    impl Default for WriteTestFixture {
        fn default() -> Self {
            let storage_data = (0..PAGE_SIZE + 1)
                .map(|i| i as u8 % u8::MAX)
                .collect::<Vec<u8>>();
            let storage_key_mem_offset = 3 * PAGE_SIZE as MemAddress;
            let storage_key_size = 150;
            let storage_data_mem_offset = 10 * PAGE_SIZE as MemAddress;
            let storage_data_size = storage_data.len();
            let mem_readable_range_for_key =
                storage_key_mem_offset..storage_key_mem_offset + storage_key_size as MemAddress;
            let mem_readable_range_for_data =
                storage_data_mem_offset..storage_data_mem_offset + storage_data_size as MemAddress;
            Self {
                accumulate_host: 0,
                accumulate_host_balance: 10_000,
                storage_key_mem_offset,
                storage_key_size,
                storage_data_mem_offset,
                storage_data_size: PAGE_SIZE + 1,
                storage_key: StorageKey::from_vec((0..storage_key_size as u8).collect::<Vec<_>>()),
                storage_data,
                prev_storage_data: Some((0..5).collect::<Vec<u8>>()),
                prev_storage_data_size: 5,
                mem_readable_range_for_key,
                mem_readable_range_for_data,
            }
        }
    }

    impl WriteTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.storage_key_mem_offset)
                .with_reg(8, self.storage_key_size as RegValue)
                .with_reg(9, self.storage_data_mem_offset)
                .with_reg(10, self.storage_data_size as RegValue)
                .with_mem_data(self.storage_key_mem_offset, self.storage_key.as_slice())?
                .with_mem_data(self.storage_data_mem_offset, self.storage_data.as_slice())
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            let provider = MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance);
            match &self.prev_storage_data {
                Some(prev_data) => provider.with_storage_entry(
                    self.accumulate_host,
                    self.storage_key.clone(),
                    AccountStorageEntry::new(Octets::from_vec(prev_data.clone())),
                ),
                None => provider,
            }
        }

        async fn prepare_invocation_context(
            &self,
            state_provider: Arc<MockStateManager>,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            Ok(
                InvocationContextBuilder::accumulate_context_builder_default(
                    state_provider,
                    self.accumulate_host,
                )
                .await?
                .build(),
            )
        }

        fn host_call_result_successful(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(self.prev_storage_data_size as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_successful_no_prev_entry() -> HostCallResult {
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

        fn host_call_result_full() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::FULL as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        async fn get_storage_entry_from_partial_state(
            &self,
            state_provider: Arc<MockStateManager>,
            context: InvocationContext<MockStateManager>,
        ) -> Result<Option<Octets>, Box<dyn Error>> {
            Ok(context
                .get_accumulate_x()
                .cloned()
                .unwrap()
                .partial_state
                .accounts_sandbox
                .get_account_storage_entry(state_provider, self.accumulate_host, &self.storage_key)
                .await?
                .map(|e| e.value.clone()))
        }
    }

    #[tokio::test]
    async fn test_write_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_key.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_for_data.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(res, fixture.host_call_result_successful());

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?
            .expect("Storage entry should exist");
        assert_eq!(storage_entry_added.0, fixture.storage_data);
        Ok(())
    }

    #[tokio::test]
    async fn test_write_successful_no_prev_entry() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture {
            prev_storage_data: None,
            prev_storage_data_size: 0,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_key.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_for_data.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(
            res,
            WriteTestFixture::host_call_result_successful_no_prev_entry()
        );

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?
            .expect("Storage entry should exist");
        assert_eq!(storage_entry_added.0, fixture.storage_data);
        Ok(())
    }

    #[tokio::test]
    async fn test_write_successful_entry_removed() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture {
            storage_data_size: 0,
            storage_data: Vec::new(),
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_key.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_for_data.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(res, fixture.host_call_result_successful());

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?;
        assert!(storage_entry_added.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_write_mem_not_readable_storage_key() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_data.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(res, WriteTestFixture::host_call_result_panic());

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?
            .expect("Storage entry should exist");
        assert_eq!(storage_entry_added.0, fixture.prev_storage_data.unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_write_mem_not_readable_storage_data() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_key.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(res, WriteTestFixture::host_call_result_panic());

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?
            .expect("Storage entry should exist");
        assert_eq!(storage_entry_added.0, fixture.prev_storage_data.unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_write_insufficient_balance() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = WriteTestFixture {
            accumulate_host_balance: 0,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_for_key.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_for_data.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let res = GeneralHostFunction::<MockStateManager>::host_write(
            fixture.accumulate_host,
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        // Check host-call result
        assert_eq!(res, WriteTestFixture::host_call_result_full());

        // Check partial state after host-call
        let storage_entry_added = fixture
            .get_storage_entry_from_partial_state(state_provider, context)
            .await?
            .expect("Storage entry should exist");
        assert_eq!(storage_entry_added.0, fixture.prev_storage_data.unwrap());
        Ok(())
    }
}
