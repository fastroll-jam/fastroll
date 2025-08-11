use crate::{
    context::InvocationContext,
    host_functions::{
        accumulate::AccumulateHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
};
use fr_codec::prelude::*;
use fr_common::{
    utils::tracing::setup_tracing, AuthHash, Balance, ByteEncodable, CodeHash, CoreIndex,
    ServiceId, SignedGas, TimeslotIndex, AUTH_QUEUE_SIZE, CORE_COUNT, HASH_SIZE,
    MIN_PUBLIC_SERVICE_ID, VALIDATOR_COUNT,
};
use fr_crypto::types::{
    BandersnatchPubKey, Ed25519PubKey, ValidatorKey, ValidatorKeySet, ValidatorKeys,
};
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, PAGE_SIZE},
    exit_reason::ExitReason,
};
use fr_state::types::{
    privileges::AssignServices, AlwaysAccumulateServices, AuthQueue, CoreAuthQueue,
    PrivilegedServices, StagingSet,
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

#[allow(dead_code)]
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
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(
            res,
            NewTestFixture::host_call_result_successful(expected_new_service_id)
        );

        // Check partial state after host-call

        // `next_new_service_id` context update (rotated)
        assert_eq!(x.next_new_service_id, fixture.updated_next_new_service_id);
        // The new service account added to the partial state
        assert!(
            x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, expected_new_service_id)
                .await?
        );
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
        let x = context.get_accumulate_x().unwrap();
        assert_eq!(res, fixture.host_call_result_successful_small_service_id());

        // Check partial state after host-call

        // `next_new_service_id` context not updated (added via registrar; no rotation)
        assert_eq!(x.next_new_service_id, fixture.prev_next_new_service_id);
        // The new service account added to the partial state
        assert!(
            x.partial_state
                .accounts_sandbox
                .account_exists(state_provider, expected_new_service_id)
                .await?
        );
        // TODO: test new account fields (e.g. parent service), parent service balance deducted
        Ok(())
    }

    #[tokio::test]
    async fn test_new_mem_not_readable() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[tokio::test]
    async fn test_new_gratis_storage_unauthorized() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[tokio::test]
    async fn test_new_insufficient_balance() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    #[tokio::test]
    async fn test_new_small_service_id_already_taken() -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
