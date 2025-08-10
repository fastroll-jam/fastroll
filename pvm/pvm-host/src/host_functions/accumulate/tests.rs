use crate::{
    context::InvocationContext,
    host_functions::{
        accumulate::AccumulateHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
};
use fr_codec::prelude::*;
use fr_common::{utils::tracing::setup_tracing, ServiceId, UnsignedGas, CORE_COUNT};
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, PAGE_SIZE},
    exit_reason::ExitReason,
};
use fr_state::types::privileges::AssignServices;
use std::{collections::BTreeMap, error::Error, ops::Range, sync::Arc};

mod bless_tests {
    use super::*;

    struct BlessTestFixture {
        accumulate_host: ServiceId,
        manager: ServiceId,
        designate: ServiceId,
        registrar: ServiceId,
        assign_services: AssignServices,
        always_accumulate_services: BTreeMap<ServiceId, UnsignedGas>,
        assign_offset: MemAddress,
        always_accumulate_offset: MemAddress,
        mem_readable_range_assign: Range<MemAddress>,
        mem_readable_range_always_accumulate: Range<MemAddress>,
    }

    impl Default for BlessTestFixture {
        fn default() -> Self {
            let assign_offset = PAGE_SIZE as MemAddress;
            let always_accumulate_offset = 2 * PAGE_SIZE as MemAddress;
            let assign_services =
                AssignServices::try_from((0..CORE_COUNT as ServiceId).collect::<Vec<_>>()).unwrap();
            let mut always_accumulate_services = BTreeMap::new();
            always_accumulate_services.insert(100, 1000);
            always_accumulate_services.insert(101, 2000);
            let mem_readable_range_assign =
                assign_offset..assign_offset + (4 * CORE_COUNT) as MemAddress;
            let mem_readable_range_always_accumulate = always_accumulate_offset
                ..always_accumulate_offset + (12 * always_accumulate_services.len()) as MemAddress;

            Self {
                accumulate_host: 1,
                manager: 10,
                designate: 20,
                registrar: 30,
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

        let res = AccumulateHostFunction::<MockStateManager>::host_bless(&vm, &mut context)?;
        assert_eq!(res, BlessTestFixture::host_call_result_successful());

        let x = context.get_accumulate_x().unwrap();
        assert_eq!(x.partial_state.manager_service, fixture.manager);
        assert_eq!(x.partial_state.assign_services, fixture.assign_services);
        assert_eq!(x.partial_state.designate_service, fixture.designate);
        assert_eq!(x.partial_state.registrar_service, fixture.registrar);
        assert_eq!(
            x.partial_state.always_accumulate_services,
            fixture.always_accumulate_services
        );
        Ok(())
    }
}
