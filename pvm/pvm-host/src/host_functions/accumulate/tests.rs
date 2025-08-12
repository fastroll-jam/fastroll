use crate::{
    context::{
        partial_state::{SandboxEntryAccessor, SandboxEntryStatus},
        InvocationContext,
    },
    host_functions::{
        accumulate::AccumulateHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
};
use fr_codec::prelude::*;
use fr_common::{
    utils::tracing::setup_tracing, AuthHash, Balance, ByteEncodable, CodeHash, CoreIndex, Hash32,
    Octets, ServiceId, SignedGas, TimeslotIndex, AUTH_QUEUE_SIZE, CORE_COUNT, HASH_SIZE,
    MIN_PUBLIC_SERVICE_ID, PREIMAGE_EXPIRATION_PERIOD, TRANSFER_MEMO_SIZE, VALIDATOR_COUNT,
};
use fr_crypto::types::{
    BandersnatchPubKey, Ed25519PubKey, ValidatorKey, ValidatorKeySet, ValidatorKeys,
};
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, PAGE_SIZE},
    exit_reason::ExitReason,
    invoke_args::{DeferredTransfer, TransferMemo},
};
use fr_state::types::{
    privileges::AssignServices, AccountLookupsEntry, AccountLookupsEntryExt,
    AccountLookupsEntryTimeslots, AccountMetadata, AccountPreimagesEntry, AlwaysAccumulateServices,
    AuthQueue, CoreAuthQueue, PrivilegedServices, StagingSet, Timeslot,
};
use std::{error::Error, ops::Range, sync::Arc};

mod bless_tests {
    use super::*;

    struct BlessTestFixture {
        accumulate_host: ServiceId,
        prev_manager: ServiceId,
        prev_designate: ServiceId,
        prev_registrar: ServiceId,
        prev_assign_services: AssignServices,
        prev_always_accumulate_services: AlwaysAccumulateServices,
        manager: RegValue,
        designate: RegValue,
        registrar: RegValue,
        assign_services: AssignServices,
        always_accumulate_services: AlwaysAccumulateServices,
        assign_offset: MemAddress,
        always_accumulate_offset: MemAddress,
        mem_readable_range_assign: Range<MemAddress>,
        mem_readable_range_always_accumulate: Range<MemAddress>,
    }

    impl Default for BlessTestFixture {
        fn default() -> Self {
            let prev_assign_services =
                AssignServices::try_from((10..10 + CORE_COUNT as ServiceId).collect::<Vec<_>>())
                    .unwrap();
            let prev_always_accumulate_services = AlwaysAccumulateServices::default();

            let assign_offset = PAGE_SIZE as MemAddress;
            let always_accumulate_offset = 2 * PAGE_SIZE as MemAddress;
            let assign_services =
                AssignServices::try_from((0..CORE_COUNT as ServiceId).collect::<Vec<_>>()).unwrap();
            let mut always_accumulate_services = AlwaysAccumulateServices::new();
            always_accumulate_services.insert(100, 1000);
            always_accumulate_services.insert(101, 2000);
            let mem_readable_range_assign =
                assign_offset..assign_offset + (4 * CORE_COUNT) as MemAddress;
            let mem_readable_range_always_accumulate = always_accumulate_offset
                ..always_accumulate_offset + (12 * always_accumulate_services.len()) as MemAddress;

            Self {
                accumulate_host: 1,
                prev_manager: 10,
                prev_designate: 20,
                prev_registrar: 30,
                prev_assign_services,
                prev_always_accumulate_services,
                manager: 110,
                designate: 120,
                registrar: 130,
                assign_services,
                always_accumulate_services,
                assign_offset,
                always_accumulate_offset,
                mem_readable_range_assign,
                mem_readable_range_always_accumulate,
            }
        }
    }

    impl BlessTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            let mut assign_services_buf = Vec::with_capacity(4 * CORE_COUNT);
            for assign_service in &self.assign_services {
                assign_service.encode_to_fixed(&mut assign_services_buf, 4)?;
            }
            let mut always_accumulates_buf =
                Vec::with_capacity(12 * self.always_accumulate_services.len());
            for (service_id, gas) in &self.always_accumulate_services {
                service_id.encode_to_fixed(&mut always_accumulates_buf, 4)?;
                gas.encode_to_fixed(&mut always_accumulates_buf, 8)?;
            }

            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.manager)
                .with_reg(8, self.assign_offset)
                .with_reg(9, self.designate)
                .with_reg(10, self.registrar)
                .with_reg(11, self.always_accumulate_offset)
                .with_reg(12, self.always_accumulate_services.len() as RegValue)
                .with_mem_data(self.assign_offset, assign_services_buf.as_slice())?
                .with_mem_data(
                    self.always_accumulate_offset,
                    always_accumulates_buf.as_slice(),
                )
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder().with_empty_account(self.accumulate_host)
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
                .with_privileged_services(PrivilegedServices {
                    manager_service: self.prev_manager,
                    assign_services: self.prev_assign_services.clone(),
                    designate_service: self.prev_designate,
                    registrar_service: self.prev_registrar,
                    always_accumulate_services: self.prev_always_accumulate_services.clone(),
                })
                .build(),
            )
        }

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_who() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::WHO as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_bless_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = BlessTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_assign.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_always_accumulate.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(
            x.partial_state.manager_service,
            fixture.manager as ServiceId
        );
        assert_eq!(x.partial_state.assign_services, fixture.assign_services);
        assert_eq!(
            x.partial_state.designate_service,
            fixture.designate as ServiceId
        );
        assert_eq!(
            x.partial_state.registrar_service,
            fixture.registrar as ServiceId
        );
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.always_accumulate_services
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_bless_invalid_service_id_manager() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = BlessTestFixture {
            manager: RegValue::MAX, // Invalid service id
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_assign.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_always_accumulate.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_who());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.prev_manager);
        assert_eq!(
            x.partial_state.assign_services,
            fixture.prev_assign_services
        );
        assert_eq!(x.partial_state.designate_service, fixture.prev_designate);
        assert_eq!(x.partial_state.registrar_service, fixture.prev_registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.prev_always_accumulate_services
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_bless_invalid_service_id_designate() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = BlessTestFixture {
            designate: RegValue::MAX, // Invalid service id
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_assign.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_always_accumulate.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_who());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.prev_manager);
        assert_eq!(
            x.partial_state.assign_services,
            fixture.prev_assign_services
        );
        assert_eq!(x.partial_state.designate_service, fixture.prev_designate);
        assert_eq!(x.partial_state.registrar_service, fixture.prev_registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.prev_always_accumulate_services
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_bless_invalid_service_id_registrar() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = BlessTestFixture {
            registrar: RegValue::MAX, // Invalid service id
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_assign.clone())?
            .with_mem_readable_range(fixture.mem_readable_range_always_accumulate.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_who());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.prev_manager);
        assert_eq!(
            x.partial_state.assign_services,
            fixture.prev_assign_services
        );
        assert_eq!(x.partial_state.designate_service, fixture.prev_designate);
        assert_eq!(x.partial_state.registrar_service, fixture.prev_registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.prev_always_accumulate_services
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_bless_mem_not_readable_assign_services() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = BlessTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_always_accumulate.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_panic());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.prev_manager);
        assert_eq!(
            x.partial_state.assign_services,
            fixture.prev_assign_services
        );
        assert_eq!(x.partial_state.designate_service, fixture.prev_designate);
        assert_eq!(x.partial_state.registrar_service, fixture.prev_registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.prev_always_accumulate_services
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_bless_mem_not_readable_always_accumulate_services() -> Result<(), Box<dyn Error>>
    {
        setup_tracing();
        let fixture = BlessTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range_assign.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_panic());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.prev_manager);
        assert_eq!(
            x.partial_state.assign_services,
            fixture.prev_assign_services
        );
        assert_eq!(x.partial_state.designate_service, fixture.prev_designate);
        assert_eq!(x.partial_state.registrar_service, fixture.prev_registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.prev_always_accumulate_services
        );
        Ok(())
    }
}

mod assign_tests {
    use super::*;

    struct AssignTestFixture {
        accumulate_host: ServiceId,
        core_index: RegValue,
        auth_offset: MemAddress,
        prev_assign_service: ServiceId,
        new_assign_service: RegValue,
        prev_auth_queue: AuthQueue,
        new_core_auth_queue: CoreAuthQueue,
        updated_auth_queue: AuthQueue,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for AssignTestFixture {
        fn default() -> Self {
            // AuthQueue prior to `ASSIGN` host call
            let mut prev_auth_queue = AuthQueue::default();
            for i in 0..CORE_COUNT {
                for j in 0..AUTH_QUEUE_SIZE {
                    let mut val = (i * AUTH_QUEUE_SIZE + j).encode().unwrap();
                    val.resize(HASH_SIZE, 0);
                    prev_auth_queue.0[i][j] = AuthHash::from_slice(&val).unwrap();
                }
            }

            // New CoreAuthQueue assignment
            let core_index = 1;
            let new_core_auth_queue = CoreAuthQueue::try_from(vec![
                AuthHash::from_hex(
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                )
                .unwrap();
                AUTH_QUEUE_SIZE
            ])
            .unwrap();

            // Updated AuthQueue after `ASSIGN` host call
            let mut updated_auth_queue = prev_auth_queue.clone();
            updated_auth_queue.0[core_index] = new_core_auth_queue.clone();

            let auth_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = auth_offset..auth_offset + 32 * AUTH_QUEUE_SIZE as MemAddress;

            Self {
                accumulate_host: 1,
                core_index: core_index as RegValue,
                auth_offset,
                prev_assign_service: 1,
                new_assign_service: 100,
                prev_auth_queue,
                new_core_auth_queue,
                updated_auth_queue,
                mem_readable_range,
            }
        }
    }

    impl AssignTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.core_index)
                .with_reg(8, self.auth_offset)
                .with_reg(9, self.new_assign_service)
                .with_mem_data(
                    self.auth_offset,
                    self.new_core_auth_queue.encode()?.as_slice(),
                )
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder().with_empty_account(self.accumulate_host)
        }

        async fn prepare_invocation_context(
            &self,
            state_provider: Arc<MockStateManager>,
            accumulate_host: Option<ServiceId>,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            let accumulate_host = accumulate_host.unwrap_or(self.accumulate_host);
            Ok(
                InvocationContextBuilder::accumulate_context_builder_default(
                    state_provider,
                    accumulate_host,
                )
                .await?
                .with_auth_queue(self.prev_auth_queue.clone())
                .with_assign_service(self.core_index as CoreIndex, self.prev_assign_service)
                .build(),
            )
        }

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_core() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::CORE as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_who() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::WHO as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_assign_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = AssignTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_assign(&vm, &mut context)?;
        assert_eq!(res, AssignTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.auth_queue, fixture.updated_auth_queue);
        assert_eq!(
            x.partial_state.assign_services[fixture.core_index as usize],
            fixture.new_assign_service as ServiceId
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_assign_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = AssignTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_assign(&vm, &mut context)?;
        assert_eq!(res, AssignTestFixture::host_call_result_panic());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.auth_queue, fixture.prev_auth_queue);
        assert_eq!(
            x.partial_state.assign_services[fixture.core_index as usize],
            fixture.prev_assign_service
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_assign_invalid_core_index() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = AssignTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(7, RegValue::MAX) // overwrite core index with invalid value
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_assign(&vm, &mut context)?;
        assert_eq!(res, AssignTestFixture::host_call_result_core());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.auth_queue, fixture.prev_auth_queue);
        assert_eq!(
            x.partial_state.assign_services[fixture.core_index as usize],
            fixture.prev_assign_service
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_assign_accumulate_host_not_assigner() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 2;
        let fixture = AssignTestFixture {
            accumulate_host,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), Some(accumulate_host))
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_assign(&vm, &mut context)?;
        assert_eq!(res, AssignTestFixture::host_call_result_huh());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.auth_queue, fixture.prev_auth_queue);
        assert_eq!(
            x.partial_state.assign_services[fixture.core_index as usize],
            fixture.prev_assign_service
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_assign_invalid_service_id() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = AssignTestFixture {
            new_assign_service: RegValue::MAX,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_assign(&vm, &mut context)?;
        assert_eq!(res, AssignTestFixture::host_call_result_who());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.auth_queue, fixture.prev_auth_queue);
        assert_eq!(
            x.partial_state.assign_services[fixture.core_index as usize],
            fixture.prev_assign_service
        );
        Ok(())
    }
}

mod designate_tests {
    use super::*;

    struct DesignateTestFixture {
        accumulate_host: ServiceId,
        staging_set_offset: MemAddress,
        prev_designator: ServiceId,
        new_staging_set: StagingSet,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for DesignateTestFixture {
        fn default() -> Self {
            let validator = ValidatorKey {
                bandersnatch: BandersnatchPubKey::from_hex("0x123").unwrap(),
                ed25519: Ed25519PubKey::from_hex("0x456").unwrap(),
                ..Default::default()
            };
            let validators = vec![validator.clone(); VALIDATOR_COUNT];
            let new_staging_set = StagingSet(ValidatorKeySet(
                ValidatorKeys::try_from(validators).unwrap(),
            ));
            let staging_set_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range =
                staging_set_offset..staging_set_offset + 336 * VALIDATOR_COUNT as MemAddress;

            Self {
                accumulate_host: 1,
                staging_set_offset,
                prev_designator: 1,
                new_staging_set,
                mem_readable_range,
            }
        }
    }

    impl DesignateTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.staging_set_offset)
                .with_mem_data(
                    self.staging_set_offset,
                    self.new_staging_set.encode()?.as_slice(),
                )
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder().with_empty_account(self.accumulate_host)
        }

        async fn prepare_invocation_context(
            &self,
            state_provider: Arc<MockStateManager>,
            accumulate_host: Option<ServiceId>,
        ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
            let accumulate_host = accumulate_host.unwrap_or(self.accumulate_host);
            Ok(
                InvocationContextBuilder::accumulate_context_builder_default(
                    state_provider,
                    accumulate_host,
                )
                .await?
                .with_designate_service(self.prev_designator)
                .build(),
            )
        }

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_designate_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = DesignateTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_designate(&vm, &mut context)?;
        assert_eq!(res, DesignateTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(
            x.partial_state.new_staging_set,
            Some(fixture.new_staging_set)
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_designate_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = DesignateTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), None)
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_designate(&vm, &mut context)?;
        assert_eq!(res, DesignateTestFixture::host_call_result_panic());

        // Check partial state after host-call
        // Partial state should remain unchanged
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.new_staging_set, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_designate_accumulate_host_not_designator() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let accumulate_host = 2;
        let fixture = DesignateTestFixture {
            accumulate_host,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone(), Some(accumulate_host))
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_designate(&vm, &mut context)?;
        assert_eq!(res, DesignateTestFixture::host_call_result_huh());

        // Check partial state after host-call
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.new_staging_set, None);
        Ok(())
    }
}

mod checkpoint_tests {
    use super::*;

    struct CheckpointTestFixture {
        accumulate_host: ServiceId,
        privileged_services: PrivilegedServices,
        prev_gas_remaining: SignedGas,
    }

    impl Default for CheckpointTestFixture {
        fn default() -> Self {
            Self {
                accumulate_host: 1,
                privileged_services: PrivilegedServices {
                    manager_service: 2,
                    assign_services: AssignServices::try_from(
                        (10..10 + CORE_COUNT as ServiceId).collect::<Vec<_>>(),
                    )
                    .unwrap(),
                    designate_service: 3,
                    registrar_service: 4,
                    always_accumulate_services: AlwaysAccumulateServices::from_iter([
                        (100, 1000),
                        (101, 2000),
                    ]),
                },
                prev_gas_remaining: 100,
            }
        }
    }

    impl CheckpointTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            Ok(VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(self.prev_gas_remaining))
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder().with_empty_account(self.accumulate_host)
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
                .with_privileged_services(PrivilegedServices {
                    manager_service: self.privileged_services.manager_service,
                    assign_services: self.privileged_services.assign_services.clone(),
                    designate_service: self.privileged_services.designate_service,
                    registrar_service: self.privileged_services.registrar_service,
                    always_accumulate_services: self
                        .privileged_services
                        .always_accumulate_services
                        .clone(),
                })
                .build(),
            )
        }

        fn host_call_result_successful(self) -> HostCallResult {
            let gas_charge = HOSTCALL_BASE_GAS_CHARGE;
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge,
                    r7_write: Some((self.prev_gas_remaining - gas_charge as SignedGas) as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_checkpoint_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = CheckpointTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Compare accumulate context X & Y before host-call
        let x = context.get_accumulate_x().unwrap();
        let y = context.get_accumulate_y().unwrap();
        assert_ne!(
            x.partial_state.manager_service,
            y.partial_state.manager_service
        );
        assert_ne!(
            x.partial_state.assign_services,
            y.partial_state.assign_services
        );
        assert_ne!(
            x.partial_state.designate_service,
            y.partial_state.designate_service
        );
        assert_ne!(
            x.partial_state.registrar_service,
            y.partial_state.registrar_service
        );
        assert_ne!(
            x.partial_state.always_accumulate_services,
            y.partial_state.always_accumulate_services
        );

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_checkpoint(&vm, &mut context)?;
        assert_eq!(res, fixture.host_call_result_successful());

        // Compare accumulate context X & Y after host-call
        let x = context.get_accumulate_x().unwrap();
        let y = context.get_accumulate_y().unwrap();
        assert_eq!(
            x.partial_state.manager_service,
            y.partial_state.manager_service
        );
        assert_eq!(
            x.partial_state.assign_services,
            y.partial_state.assign_services
        );
        assert_eq!(
            x.partial_state.designate_service,
            y.partial_state.designate_service
        );
        assert_eq!(
            x.partial_state.registrar_service,
            y.partial_state.registrar_service
        );
        assert_eq!(
            x.partial_state.always_accumulate_services,
            y.partial_state.always_accumulate_services
        );
        Ok(())
    }
}

mod new_tests {
    use super::*;

    const MANAGER_SERVICE: ServiceId = 2;
    const REGISTRAR_SERVICE: ServiceId = 3;

    struct NewTestFixture {
        accumulate_host: ServiceId,
        manager_service: ServiceId,
        registrar_service: ServiceId,
        accumulate_host_balance: Balance,
        code_hash_offset: MemAddress,
        code_length: RegValue,
        gas_limit_accumulate: RegValue,
        gas_limit_on_transfer: RegValue,
        gratis_storage_offset: RegValue,
        new_small_service_id: RegValue,
        code_hash: CodeHash,
        mem_readable_range: Range<MemAddress>,
        curr_timeslot_index: TimeslotIndex,
        prev_next_new_service_id: ServiceId,
        updated_next_new_service_id: ServiceId,
    }

    impl Default for NewTestFixture {
        fn default() -> Self {
            let code_hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = code_hash_offset..code_hash_offset + HASH_SIZE as MemAddress;
            let prev_next_new_service_id = 1 << 16;
            let s = MIN_PUBLIC_SERVICE_ID as u64;
            let updated_next_new_service_id = (s
                + (prev_next_new_service_id as u64 - s + 42) % ((1 << 32) - s - (1 << 8)))
                as ServiceId;
            Self {
                accumulate_host: 1,
                manager_service: MANAGER_SERVICE,
                registrar_service: REGISTRAR_SERVICE,
                accumulate_host_balance: 10_000_000,
                code_hash_offset,
                code_length: 30_000,
                gas_limit_accumulate: 100,
                gas_limit_on_transfer: 100,
                gratis_storage_offset: 0,
                new_small_service_id: MIN_PUBLIC_SERVICE_ID as RegValue + 1,
                code_hash: CodeHash::from_hex("0x123").unwrap(),
                mem_readable_range,
                curr_timeslot_index: 10,
                prev_next_new_service_id,
                updated_next_new_service_id,
            }
        }
    }

    impl NewTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.code_hash_offset)
                .with_reg(8, self.code_length)
                .with_reg(9, self.gas_limit_accumulate)
                .with_reg(10, self.gas_limit_on_transfer)
                .with_reg(11, self.gratis_storage_offset)
                .with_reg(12, self.new_small_service_id)
                .with_mem_data(self.code_hash_offset, self.code_hash.as_slice())
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
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
                .with_next_new_service_id(self.prev_next_new_service_id)
                .with_manager_service(self.manager_service)
                .with_registrar_service(self.registrar_service)
                .build(),
            )
        }

        fn host_call_result_successful(new_service_id: ServiceId) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(new_service_id as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_successful_small_service_id(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(self.new_small_service_id),
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

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_cash() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::CASH as RegValue),
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

        async fn validate_new_account(
            context: &mut InvocationContext<MockStateManager>,
            state_provider: Arc<MockStateManager>,
            fixture: NewTestFixture,
            expected_new_service_id: ServiceId,
        ) -> Result<(), Box<dyn Error>> {
            // The new service account added to the partial state
            let x = context.get_accumulate_x().unwrap();
            assert!(
                x.partial_state
                    .accounts_sandbox
                    .account_exists(state_provider.clone(), expected_new_service_id)
                    .await?
            );

            // Check new account fields
            let x_mut = context.get_mut_accumulate_x().unwrap();
            let new_account = x_mut
                .partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider.clone(), expected_new_service_id)
                .await?
                .unwrap()
                .clone();
            assert_eq!(new_account.code_hash, fixture.code_hash);
            assert_eq!(
                x_mut
                    .partial_state
                    .accounts_sandbox
                    .get_account_lookups_entry(
                        state_provider.clone(),
                        expected_new_service_id,
                        &(fixture.code_hash, fixture.code_length as u32)
                    )
                    .await?
                    .expect("Lookups entry should be inserted with empty timeslot"),
                AccountLookupsEntryExt {
                    preimage_length: fixture.code_length as u32,
                    entry: AccountLookupsEntry {
                        value: vec![].try_into().unwrap()
                    }
                }
            );
            assert_eq!(
                new_account.balance,
                AccountMetadata::get_initial_threshold_balance(
                    fixture.code_length as u32,
                    fixture.gratis_storage_offset
                )
            );
            assert_eq!(
                new_account.gas_limit_accumulate,
                fixture.gas_limit_accumulate
            );
            assert_eq!(
                new_account.gas_limit_on_transfer,
                fixture.gas_limit_on_transfer
            );
            assert_eq!(new_account.created_at, fixture.curr_timeslot_index);
            assert_eq!(
                new_account.gratis_storage_offset,
                fixture.gratis_storage_offset
            );
            assert_eq!(new_account.last_accumulate_at, 0);
            assert_eq!(new_account.parent_service_id, fixture.accumulate_host);

            // Accumulate host balance should be deducted by the threshold balance of the new account
            assert_eq!(
                x_mut
                    .partial_state
                    .accounts_sandbox
                    .get_account_metadata(state_provider, fixture.accumulate_host)
                    .await?
                    .unwrap()
                    .balance,
                fixture.accumulate_host_balance
                    - AccountMetadata::get_initial_threshold_balance(
                        fixture.code_length as u32,
                        fixture.gratis_storage_offset
                    )
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_new_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = NewTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let prev_x = context.get_accumulate_x().unwrap();
        let expected_new_service_id = prev_x.next_new_service_id;
        // New account is not yet added
        assert!(
            !prev_x
                .partial_state
                .accounts_sandbox
                .account_exists(state_provider.clone(), expected_new_service_id)
                .await?
        );

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(
            res,
            NewTestFixture::host_call_result_successful(expected_new_service_id)
        );

        // Check partial state after host-call

        // `next_new_service_id` context update (rotated)
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.next_new_service_id, fixture.updated_next_new_service_id);

        // Validate new account fields
        NewTestFixture::validate_new_account(
            &mut context,
            state_provider,
            fixture,
            expected_new_service_id,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_new_successful_small_service_id() -> Result<(), Box<dyn Error>> {
        let small_service_id = 200 as ServiceId;
        // Invoke as registrar service
        let fixture = NewTestFixture {
            accumulate_host: REGISTRAR_SERVICE,
            new_small_service_id: small_service_id as RegValue,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(12, small_service_id)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let prev_x = context.get_accumulate_x().unwrap();
        let expected_new_service_id = small_service_id;
        // New account is not yet added
        assert!(
            !prev_x
                .partial_state
                .accounts_sandbox
                .account_exists(state_provider.clone(), expected_new_service_id)
                .await?
        );

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful_small_service_id());

        // Check partial state after host-call

        // `next_new_service_id` context not updated (added via registrar; no rotation)
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.next_new_service_id, fixture.prev_next_new_service_id);

        // Validate new account fields
        NewTestFixture::validate_new_account(
            &mut context,
            state_provider,
            fixture,
            expected_new_service_id,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_new_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = NewTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, NewTestFixture::host_call_result_panic());

        // No new account added
        let x = context.get_accumulate_x().unwrap();
        assert!(
            !x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, x.next_new_service_id)
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_new_gratis_storage_unauthorized() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = NewTestFixture {
            gratis_storage_offset: 100,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, NewTestFixture::host_call_result_huh());

        // No new account added
        let x = context.get_accumulate_x().unwrap();
        assert!(
            !x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, x.next_new_service_id)
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_new_insufficient_balance() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = NewTestFixture {
            accumulate_host_balance: 10_000, // Insufficient balance
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, NewTestFixture::host_call_result_cash());

        // No new account added
        let x = context.get_accumulate_x().unwrap();
        assert!(
            !x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, x.next_new_service_id)
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_new_small_service_id_already_taken() -> Result<(), Box<dyn Error>> {
        let small_service_id = REGISTRAR_SERVICE; // already taken (initialized as accumulate host)

        // Invoke as registrar service
        let fixture = NewTestFixture {
            accumulate_host: REGISTRAR_SERVICE,
            new_small_service_id: small_service_id as RegValue,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_reg(12, small_service_id)
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_new(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, NewTestFixture::host_call_result_full());

        // No new account added
        let x = context.get_accumulate_x().unwrap();
        assert!(
            !x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, x.next_new_service_id)
                .await?
        );
        Ok(())
    }
}

mod upgrade_tests {
    use super::*;

    struct UpgradeTestFixture {
        accumulate_host: ServiceId,
        code_hash_offset: MemAddress,
        gas_limit_accumulate: RegValue,
        gas_limit_on_transfer: RegValue,
        code_hash: CodeHash,
        prev_gas_limit_accumulate: RegValue,
        prev_gas_limit_on_transfer: RegValue,
        prev_code_hash: CodeHash,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for UpgradeTestFixture {
        fn default() -> Self {
            let code_hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = code_hash_offset..code_hash_offset + HASH_SIZE as MemAddress;
            Self {
                accumulate_host: 1,
                code_hash_offset,
                gas_limit_accumulate: 200,
                gas_limit_on_transfer: 100,
                code_hash: CodeHash::from_hex("0x123").unwrap(),
                prev_gas_limit_accumulate: 2,
                prev_gas_limit_on_transfer: 1,
                prev_code_hash: CodeHash::from_hex("0x1").unwrap(),
                mem_readable_range,
            }
        }
    }

    impl UpgradeTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.code_hash_offset)
                .with_reg(8, self.gas_limit_accumulate)
                .with_reg(9, self.gas_limit_on_transfer)
                .with_mem_data(self.code_hash_offset, self.code_hash.as_slice())
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder().with_account(
                self.accumulate_host,
                AccountMetadata {
                    code_hash: self.prev_code_hash.clone(),
                    gas_limit_accumulate: self.prev_gas_limit_accumulate,
                    gas_limit_on_transfer: self.prev_gas_limit_on_transfer,
                    ..Default::default()
                },
            )
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

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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
    async fn test_upgrade_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = UpgradeTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_upgrade(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, UpgradeTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        let accumulate_host_upgraded = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider, fixture.accumulate_host)
            .await?
            .expect("Accumulate host must exist in the partial state");

        assert_eq!(accumulate_host_upgraded.code_hash, fixture.code_hash);
        assert_eq!(
            accumulate_host_upgraded.gas_limit_accumulate,
            fixture.gas_limit_accumulate
        );
        assert_eq!(
            accumulate_host_upgraded.gas_limit_on_transfer,
            fixture.gas_limit_on_transfer
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_upgrade_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = UpgradeTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_upgrade(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, UpgradeTestFixture::host_call_result_panic());

        // Accumulate host account should remain unchanged
        let x = context.get_mut_accumulate_x().unwrap();
        let accumulate_host = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider, fixture.accumulate_host)
            .await?
            .expect("Accumulate host must exist in the partial state");

        assert_eq!(accumulate_host.code_hash, fixture.prev_code_hash);
        assert_eq!(
            accumulate_host.gas_limit_accumulate,
            fixture.prev_gas_limit_accumulate
        );
        assert_eq!(
            accumulate_host.gas_limit_on_transfer,
            fixture.prev_gas_limit_on_transfer
        );
        Ok(())
    }
}

mod transfer_tests {
    use super::*;

    struct TransferTestFixture {
        accumulate_host: ServiceId,
        accumulate_host_balance: Balance,
        transfer_destination: RegValue,
        transfer_amount: RegValue,
        transfer_gas_limit: RegValue,
        memo_offset: MemAddress,
        memo: TransferMemo,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for TransferTestFixture {
        fn default() -> Self {
            let memo_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = memo_offset..memo_offset + TRANSFER_MEMO_SIZE as MemAddress;
            Self {
                accumulate_host: 1,
                accumulate_host_balance: 1_000_000,
                transfer_destination: 2,
                transfer_amount: 50_000,
                transfer_gas_limit: 100,
                memo_offset,
                memo: TransferMemo::from_hex("0x616263").unwrap(),
                mem_readable_range,
            }
        }
    }

    impl TransferTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(150)
                .with_reg(7, self.transfer_destination)
                .with_reg(8, self.transfer_amount)
                .with_reg(9, self.transfer_gas_limit)
                .with_reg(10, self.memo_offset)
                .with_mem_data(self.memo_offset, self.memo.as_slice())
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_account(
                    self.transfer_destination as ServiceId,
                    AccountMetadata {
                        gas_limit_on_transfer: 100,
                        ..Default::default()
                    },
                )
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
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE + self.transfer_gas_limit,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_panic(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Panic,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE + self.transfer_gas_limit,
                    r7_write: None,
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_who(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE + self.transfer_gas_limit,
                    r7_write: Some(HostCallReturnCode::WHO as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_low(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE + self.transfer_gas_limit,
                    r7_write: Some(HostCallReturnCode::LOW as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_cash(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE + self.transfer_gas_limit,
                    r7_write: Some(HostCallReturnCode::CASH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn expected_deferred_transfer(&self) -> DeferredTransfer {
            DeferredTransfer {
                from: self.accumulate_host,
                to: self.transfer_destination as ServiceId,
                amount: self.transfer_amount,
                memo: TransferMemo::try_from(self.memo.clone()).unwrap(),
                gas_limit: self.transfer_gas_limit,
            }
        }
    }

    #[tokio::test]
    async fn test_transfer_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = TransferTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_transfer(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        // Deferred transfer added
        assert_eq!(
            x.deferred_transfers[x.deferred_transfers.len() - 1].clone(),
            fixture.expected_deferred_transfer()
        );
        // Sender balance deducted
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider, fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance,
            fixture.accumulate_host_balance - fixture.transfer_amount
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = TransferTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let x = context.get_accumulate_x().unwrap();
        let prev_deferred_transfers = x.deferred_transfers.clone();

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_transfer(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_panic());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        // Deferred transfer not added
        assert_eq!(x.deferred_transfers, prev_deferred_transfers);
        // Sender balance unchanged
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider, fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance,
            fixture.accumulate_host_balance
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_destination_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let mut fixture = TransferTestFixture::default();

        let state_provider = Arc::new(fixture.prepare_state_provider());

        // Change transfer destination to an account that doesn't exist in the `MockStateManager`
        fixture.transfer_destination = 3;

        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();

        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let x = context.get_accumulate_x().unwrap();
        let prev_deferred_transfers = x.deferred_transfers.clone();

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_transfer(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_who());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        // Deferred transfer not added
        assert_eq!(x.deferred_transfers, prev_deferred_transfers);
        // Sender balance unchanged
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider, fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance,
            fixture.accumulate_host_balance
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_low_gas_limit() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = TransferTestFixture {
            transfer_gas_limit: 50,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let x = context.get_accumulate_x().unwrap();
        let prev_deferred_transfers = x.deferred_transfers.clone();

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_transfer(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_low());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        // Deferred transfer not added
        assert_eq!(x.deferred_transfers, prev_deferred_transfers);
        // Sender balance unchanged
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider, fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance,
            fixture.accumulate_host_balance
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_transfer_insufficient_balance() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = TransferTestFixture {
            accumulate_host_balance: 0, // Insufficient balance
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        let x = context.get_accumulate_x().unwrap();
        let prev_deferred_transfers = x.deferred_transfers.clone();

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_transfer(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_cash());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        // Deferred transfer not added
        assert_eq!(x.deferred_transfers, prev_deferred_transfers);
        // Sender balance unchanged
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider, fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance,
            fixture.accumulate_host_balance
        );
        Ok(())
    }
}

mod eject_tests {
    use super::*;

    struct EjectTestFixture {
        accumulate_host: ServiceId,
        accumulate_host_balance: Balance,
        eject_service: ServiceId,
        eject_service_balance: Balance,
        eject_service_code_hash: CodeHash,
        hash_offset: MemAddress,
        last_preimage_hash: Hash32,
        last_preimage_size: u32,
        eject_service_octets_footprint: u64,
        eject_service_items_footprint: u32,
        curr_timeslot_index: TimeslotIndex,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for EjectTestFixture {
        fn default() -> Self {
            let accumulate_host = 1;
            let hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = hash_offset..hash_offset + HASH_SIZE as MemAddress;
            let eject_service_octets_footprint = 200u64;
            let curr_timeslot_index = 20_000;
            let mut accumulate_host_encoded_32 = accumulate_host.encode_fixed(4).unwrap();
            accumulate_host_encoded_32.resize(32, 0);
            Self {
                accumulate_host,
                accumulate_host_balance: 100,
                eject_service: 2,
                eject_service_balance: 150,
                eject_service_code_hash: CodeHash::from_slice(
                    accumulate_host_encoded_32.as_slice(),
                )
                .unwrap(),
                hash_offset,
                last_preimage_hash: Hash32::from_hex("0x123").unwrap(),
                last_preimage_size: 81.max(eject_service_octets_footprint as u32) - 81,
                eject_service_octets_footprint,
                eject_service_items_footprint: 2,
                curr_timeslot_index,
                mem_readable_range,
            }
        }
    }

    impl EjectTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.eject_service)
                .with_reg(8, self.hash_offset)
                .with_mem_data(self.hash_offset, self.last_preimage_hash.as_slice())
        }

        fn prepare_state_provider(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_account(
                    self.eject_service,
                    AccountMetadata {
                        balance: self.eject_service_balance,
                        code_hash: self.eject_service_code_hash.clone(),
                        items_footprint: self.eject_service_items_footprint,
                        octets_footprint: self.eject_service_octets_footprint,
                        ..Default::default()
                    },
                )
                .with_lookups_entry(
                    self.eject_service,
                    (self.last_preimage_hash.clone(), self.last_preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            Timeslot::new(
                                self.curr_timeslot_index - PREIMAGE_EXPIRATION_PERIOD - 2,
                            ),
                            Timeslot::new(
                                self.curr_timeslot_index - PREIMAGE_EXPIRATION_PERIOD - 1,
                            ),
                        ])
                        .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_preimage_not_forgotten(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_account(
                    self.eject_service,
                    AccountMetadata {
                        balance: self.eject_service_balance,
                        code_hash: self.eject_service_code_hash.clone(),
                        items_footprint: self.eject_service_items_footprint,
                        octets_footprint: self.eject_service_octets_footprint,
                        ..Default::default()
                    },
                )
                .with_lookups_entry(
                    self.eject_service,
                    (self.last_preimage_hash.clone(), self.last_preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![Timeslot::new(
                            self.curr_timeslot_index - PREIMAGE_EXPIRATION_PERIOD - 2,
                        )])
                        .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_preimage_not_expired(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_account(
                    self.eject_service,
                    AccountMetadata {
                        balance: self.eject_service_balance,
                        code_hash: self.eject_service_code_hash.clone(),
                        items_footprint: self.eject_service_items_footprint,
                        octets_footprint: self.eject_service_octets_footprint,
                        ..Default::default()
                    },
                )
                .with_lookups_entry(
                    self.eject_service,
                    (self.last_preimage_hash.clone(), self.last_preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            Timeslot::new(
                                self.curr_timeslot_index - PREIMAGE_EXPIRATION_PERIOD - 2,
                            ),
                            Timeslot::new(self.curr_timeslot_index - PREIMAGE_EXPIRATION_PERIOD),
                        ])
                        .unwrap(),
                    },
                )
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

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_who() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::WHO as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        async fn assert_partial_state_unchanged(
            fixture: &EjectTestFixture,
            context: &mut InvocationContext<MockStateManager>,
            state_provider: Arc<MockStateManager>,
        ) -> Result<(), Box<dyn Error>> {
            let x = context.get_mut_accumulate_x().unwrap();

            // accumulate host balance remains unchanged
            let accumulate_host_balance_updated = x
                .partial_state
                .accounts_sandbox
                .get_account_metadata(state_provider.clone(), fixture.accumulate_host)
                .await?
                .expect("Accumulate host must exist in the partial state")
                .balance;
            assert_eq!(
                accumulate_host_balance_updated,
                fixture.accumulate_host_balance
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_eject_successful() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();

        // accumulate host balance added by the eject service balance
        let accumulate_host_balance_updated = x
            .partial_state
            .accounts_sandbox
            .get_account_metadata(state_provider.clone(), fixture.accumulate_host)
            .await?
            .expect("Accumulate host must exist in the partial state")
            .balance;
        assert_eq!(
            accumulate_host_balance_updated,
            fixture.accumulate_host_balance + fixture.eject_service_balance
        );

        // eject service account removed from the partial state
        assert!(
            !x.partial_state
                .accounts_sandbox
                .account_exists(state_provider.clone(), fixture.eject_service)
                .await?
                || x.partial_state
                    .accounts_sandbox
                    .get_account_sandbox(state_provider, fixture.eject_service)
                    .await?
                    .unwrap()
                    .metadata
                    .status()
                    == &SandboxEntryStatus::Removed
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_panic());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_accumulate_host() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let mut fixture = EjectTestFixture::default();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        // attempt to eject accumulate host
        fixture.eject_service = fixture.accumulate_host;
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_who());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_account_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let mut fixture = EjectTestFixture::default();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        // attempt to eject an account that doesn't exists (not initialized in the state provider)
        fixture.eject_service = ServiceId::MAX;
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_who());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_code_hash_not_set() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture {
            eject_service_code_hash: CodeHash::from_hex("0x123").unwrap(),
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_who());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_invalid_items_footprint() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture {
            eject_service_items_footprint: 3,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_huh());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_lookups_key_not_found() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let mut fixture = EjectTestFixture::default();
        let state_provider = Arc::new(fixture.prepare_state_provider());
        fixture.last_preimage_hash = Hash32::from_hex("0x999").unwrap(); // Making lookups key invalid
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_huh());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_preimage_not_forgotten() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_preimage_not_forgotten());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_huh());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_eject_preimage_not_expired() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = EjectTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_preimage_not_expired());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_eject(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, EjectTestFixture::host_call_result_huh());

        // Check partial state after host-call
        EjectTestFixture::assert_partial_state_unchanged(&fixture, &mut context, state_provider)
            .await?;
        Ok(())
    }
}

mod query_tests {
    use super::*;

    struct QueryTestFixture {
        accumulate_host: ServiceId,
        hash_offset: MemAddress,
        preimage_size: u32,
        timeslot_x: Timeslot,
        timeslot_y: Timeslot,
        timeslot_z: Timeslot,
        preimage_hash: Hash32,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for QueryTestFixture {
        fn default() -> Self {
            let hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = hash_offset..hash_offset + HASH_SIZE as MemAddress;
            Self {
                accumulate_host: 1,
                hash_offset,
                preimage_size: 100,
                timeslot_x: Timeslot::new(1),
                timeslot_y: Timeslot::new(2),
                timeslot_z: Timeslot::new(3),
                preimage_hash: Hash32::from_hex("0xffff").unwrap(),
                mem_readable_range,
            }
        }
    }

    impl QueryTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.hash_offset)
                .with_reg(8, self.preimage_size)
                .with_mem_data(self.hash_offset, self.preimage_hash.as_slice())
        }

        fn prepare_state_provider_timeslots_0(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![]).unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_1(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![self.timeslot_x])
                            .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_2(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            self.timeslot_x,
                            self.timeslot_y,
                        ])
                        .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_3(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            self.timeslot_x,
                            self.timeslot_y,
                            self.timeslot_z,
                        ])
                        .unwrap(),
                    },
                )
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

        fn host_call_result_successful_timeslots_0() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(0),
                    r8_write: Some(0),
                    memory_write: None,
                },
            }
        }

        fn host_call_result_successful_timeslots_1(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(1 + (1 << 32) * self.timeslot_x.slot() as RegValue),
                    r8_write: Some(0),
                    memory_write: None,
                },
            }
        }

        fn host_call_result_successful_timeslots_2(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(2 + (1 << 32) * self.timeslot_x.slot() as RegValue),
                    r8_write: Some(self.timeslot_y.slot() as RegValue),
                    memory_write: None,
                },
            }
        }

        fn host_call_result_successful_timeslots_3(&self) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(3 + (1 << 32) * self.timeslot_x.slot() as RegValue),
                    r8_write: Some(
                        self.timeslot_y.slot() as RegValue
                            + (1 << 32) * self.timeslot_z.slot() as RegValue,
                    ),
                    memory_write: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn test_query_successful_timeslots_0() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = QueryTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_0());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_query(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(
            res,
            QueryTestFixture::host_call_result_successful_timeslots_0()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_query_successful_timeslots_1() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = QueryTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_1());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_query(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful_timeslots_1());
        Ok(())
    }

    #[tokio::test]
    async fn test_query_successful_timeslots_2() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = QueryTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_2());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_query(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful_timeslots_2());
        Ok(())
    }

    #[tokio::test]
    async fn test_query_successful_timeslots_3() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = QueryTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_3());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_query(
            &vm,
            state_provider.clone(),
            &mut context,
        )
        .await?;
        assert_eq!(res, fixture.host_call_result_successful_timeslots_3());
        Ok(())
    }
}

mod solicit_tests {
    use super::*;

    struct SolicitTestFixture {
        accumulate_host: ServiceId,
        accumulate_host_balance: Balance,
        hash_offset: MemAddress,
        preimage_size: u32,
        timeslot_x: Timeslot,
        timeslot_y: Timeslot,
        curr_timeslot_index: TimeslotIndex,
        preimage_hash: Hash32,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for SolicitTestFixture {
        fn default() -> Self {
            let hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = hash_offset..hash_offset + HASH_SIZE as MemAddress;
            Self {
                accumulate_host: 1,
                accumulate_host_balance: 100_000,
                hash_offset,
                preimage_size: 100,
                timeslot_x: Timeslot::new(1),
                timeslot_y: Timeslot::new(2),
                curr_timeslot_index: 3,
                preimage_hash: Hash32::from_hex("0xffff").unwrap(),
                mem_readable_range,
            }
        }
    }

    impl SolicitTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.hash_offset)
                .with_reg(8, self.preimage_size)
                .with_mem_data(self.hash_offset, self.preimage_hash.as_slice())
        }

        fn prepare_state_provider_no_lookups_entry(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
        }

        fn prepare_state_provider_timeslots_1(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![self.timeslot_x])
                            .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_2(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_balance(self.accumulate_host, self.accumulate_host_balance)
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            self.timeslot_x,
                            self.timeslot_y,
                        ])
                        .unwrap(),
                    },
                )
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

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
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
    }

    #[tokio::test]
    async fn test_solicit_successful_create_lookups_entry() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = SolicitTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_no_lookups_entry());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_solicit(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, SolicitTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        let lookups_entry_updated = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(
                state_provider,
                fixture.accumulate_host,
                &(fixture.preimage_hash.clone(), fixture.preimage_size),
            )
            .await?;
        assert!(lookups_entry_updated.is_some());
        assert_eq!(
            lookups_entry_updated.unwrap().entry.value,
            AccountLookupsEntryTimeslots::try_from(vec![])?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_solicit_successful_push_timeslot() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = SolicitTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_2());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_solicit(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, SolicitTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        let lookups_entry_updated = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(
                state_provider,
                fixture.accumulate_host,
                &(fixture.preimage_hash.clone(), fixture.preimage_size),
            )
            .await?
            .expect("Lookups inserted during initialization");
        assert_eq!(
            lookups_entry_updated.entry.value,
            AccountLookupsEntryTimeslots::try_from(vec![
                fixture.timeslot_x,
                fixture.timeslot_y,
                Timeslot::new(fixture.curr_timeslot_index)
            ])?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_solicit_mem_not_readable() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = SolicitTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_2());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_solicit(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, SolicitTestFixture::host_call_result_panic());
        Ok(())
    }

    #[tokio::test]
    async fn test_solicit_preimage_already_provided() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = SolicitTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_1());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_solicit(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, SolicitTestFixture::host_call_result_huh());

        // Check partial state after host-call (should remain unchanged)
        let x = context.get_mut_accumulate_x().unwrap();
        let lookups_entry_updated = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(
                state_provider,
                fixture.accumulate_host,
                &(fixture.preimage_hash.clone(), fixture.preimage_size),
            )
            .await?
            .expect("Lookups inserted during initialization");
        assert_eq!(
            lookups_entry_updated.entry.value,
            AccountLookupsEntryTimeslots::try_from(vec![fixture.timeslot_x,])?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_solicit_insufficient_balance() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = SolicitTestFixture {
            accumulate_host_balance: 100, // Insufficient balance
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_no_lookups_entry());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_solicit(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, SolicitTestFixture::host_call_result_full());

        // Check partial state after host-call (should remain unchanged)
        let x = context.get_mut_accumulate_x().unwrap();
        let lookups_entry_updated = x
            .partial_state
            .accounts_sandbox
            .get_account_lookups_entry(
                state_provider,
                fixture.accumulate_host,
                &(fixture.preimage_hash.clone(), fixture.preimage_size),
            )
            .await?;
        assert!(lookups_entry_updated.is_none());
        Ok(())
    }
}

mod forget_tests {
    use super::*;

    struct ForgetTestFixture {
        accumulate_host: ServiceId,
        hash_offset: MemAddress,
        preimage_size: u32,
        timeslot_x: Timeslot,
        timeslot_y: Timeslot,
        timeslot_z: Timeslot,
        curr_timeslot_index: TimeslotIndex,
        preimage_hash: Hash32,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for ForgetTestFixture {
        fn default() -> Self {
            let hash_offset = PAGE_SIZE as MemAddress;
            let mem_readable_range = hash_offset..hash_offset + HASH_SIZE as MemAddress;
            Self {
                accumulate_host: 1,
                hash_offset,
                preimage_size: 100,
                timeslot_x: Timeslot::new(1),
                timeslot_y: Timeslot::new(2),
                timeslot_z: Timeslot::new(3),
                curr_timeslot_index: 1000,
                preimage_hash: Hash32::from_hex("0xffff").unwrap(),
                mem_readable_range,
            }
        }
    }

    impl ForgetTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_pc(0)
                .with_gas_counter(100)
                .with_reg(7, self.hash_offset)
                .with_reg(8, self.preimage_size)
                .with_mem_data(self.hash_offset, self.preimage_hash.as_slice())
        }

        fn prepare_state_provider_no_lookups_entry(&self) -> MockStateManager {
            MockStateManager::builder().with_empty_account(self.accumulate_host)
        }

        fn prepare_state_provider_timeslots_0(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_preimages_entry(
                    self.accumulate_host,
                    self.preimage_hash.clone(),
                    AccountPreimagesEntry {
                        value: Octets::from_vec(vec![0; self.preimage_size as usize]),
                    },
                )
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![]).unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_1(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_preimages_entry(
                    self.accumulate_host,
                    self.preimage_hash.clone(),
                    AccountPreimagesEntry {
                        value: Octets::from_vec(vec![0; self.preimage_size as usize]),
                    },
                )
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![self.timeslot_x])
                            .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_2(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_preimages_entry(
                    self.accumulate_host,
                    self.preimage_hash.clone(),
                    AccountPreimagesEntry {
                        value: Octets::from_vec(vec![0; self.preimage_size as usize]),
                    },
                )
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            self.timeslot_x,
                            self.timeslot_y,
                        ])
                        .unwrap(),
                    },
                )
        }

        fn prepare_state_provider_timeslots_3(&self) -> MockStateManager {
            MockStateManager::builder()
                .with_empty_account(self.accumulate_host)
                .with_preimages_entry(
                    self.accumulate_host,
                    self.preimage_hash.clone(),
                    AccountPreimagesEntry {
                        value: Octets::from_vec(vec![0; self.preimage_size as usize]),
                    },
                )
                .with_lookups_entry(
                    self.accumulate_host,
                    (self.preimage_hash.clone(), self.preimage_size),
                    AccountLookupsEntry {
                        value: AccountLookupsEntryTimeslots::try_from(vec![
                            self.timeslot_x,
                            self.timeslot_y,
                            self.timeslot_z,
                        ])
                        .unwrap(),
                    },
                )
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

        fn host_call_result_successful() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::OK as RegValue),
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

        fn host_call_result_huh() -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(HostCallReturnCode::HUH as RegValue),
                    r8_write: None,
                    memory_write: None,
                },
            }
        }

        async fn assert_preimages_and_lookups_entries_removed(
            context: &mut InvocationContext<MockStateManager>,
            state_provider: Arc<MockStateManager>,
            fixture: &ForgetTestFixture,
        ) -> Result<(), Box<dyn Error>> {
            let x = context.get_mut_accumulate_x().unwrap();
            // preimages & lookups entries removed from the partial state
            assert!(x
                .partial_state
                .accounts_sandbox
                .get_account_preimages_entry(
                    state_provider.clone(),
                    fixture.accumulate_host,
                    &fixture.preimage_hash
                )
                .await?
                .is_none());
            assert!(x
                .partial_state
                .accounts_sandbox
                .get_account_lookups_entry(
                    state_provider.clone(),
                    fixture.accumulate_host,
                    &(fixture.preimage_hash.clone(), fixture.preimage_size)
                )
                .await?
                .is_none());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_forget_successful_timeslots_0() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_0());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_successful());

        // Check partial state after host-call
        // preimages & lookups entries removed from the partial state
        ForgetTestFixture::assert_preimages_and_lookups_entries_removed(
            &mut context,
            state_provider,
            &fixture,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_forget_successful_timeslots_1() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_1());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_lookups_entry(
                    state_provider.clone(),
                    fixture.accumulate_host,
                    &(fixture.preimage_hash.clone(), fixture.preimage_size)
                )
                .await?
                .unwrap()
                .entry,
            AccountLookupsEntry {
                value: AccountLookupsEntryTimeslots::try_from(vec![
                    fixture.timeslot_x,
                    Timeslot::new(fixture.curr_timeslot_index)
                ])
                .unwrap()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_forget_successful_timeslots_2() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_2());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_successful());

        // Check partial state after host-call
        // preimages & lookups entries removed from the partial state
        ForgetTestFixture::assert_preimages_and_lookups_entries_removed(
            &mut context,
            state_provider,
            &fixture,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_forget_successful_timeslots_3() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_3());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_successful());

        // Check partial state after host-call
        let x = context.get_mut_accumulate_x().unwrap();
        assert_eq!(
            x.partial_state
                .accounts_sandbox
                .get_account_lookups_entry(
                    state_provider.clone(),
                    fixture.accumulate_host,
                    &(fixture.preimage_hash.clone(), fixture.preimage_size)
                )
                .await?
                .unwrap()
                .entry,
            AccountLookupsEntry {
                value: AccountLookupsEntryTimeslots::try_from(vec![
                    fixture.timeslot_z,
                    Timeslot::new(fixture.curr_timeslot_index)
                ])
                .unwrap()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_forget_mem_not_readable() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_0());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_panic());

        Ok(())
    }

    #[tokio::test]
    async fn test_forget_lookups_entry_not_found() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_no_lookups_entry());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_huh());
        Ok(())
    }

    #[tokio::test]
    async fn test_forget_preimage_not_expired() -> Result<(), Box<dyn Error>> {
        let fixture = ForgetTestFixture {
            curr_timeslot_index: 4,
            ..Default::default()
        };
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let state_provider = Arc::new(fixture.prepare_state_provider_timeslots_2());
        let mut context = fixture
            .prepare_invocation_context(state_provider.clone())
            .await?;

        // Check host-call result
        let res = AccumulateHostFunction::<MockStateManager>::host_forget(
            &vm,
            state_provider.clone(),
            &mut context,
            fixture.curr_timeslot_index,
        )
        .await?;
        assert_eq!(res, ForgetTestFixture::host_call_result_huh());
        Ok(())
    }
}
