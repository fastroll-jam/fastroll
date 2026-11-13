use crate::{
    context::InvocationContext,
    host_functions::{
        refine::RefineHostFunction,
        test_utils::{InvocationContextBuilder, MockStateManager, VMStateBuilder},
        HostCallResult, HostCallReturnCode,
    },
    inner_vm::InnerPVM,
};
use fr_common::utils::tracing::setup_tracing;
use fr_pvm_core::state::state_change::HostCallVMStateChange;
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, INIT_ZONE_SIZE, MAX_INNER_PVM_INSTANCES, PAGE_SIZE},
    exit_reason::ExitReason,
};
use std::{error::Error, ops::Range};

mod machine_tests {
    use super::*;

    struct MachineTestFixture {
        program_offset: MemAddress,
        // a blob with an empty jump table and a single `trap` instruction
        program: Vec<u8>,
        initial_pc: RegValue,
        mem_readable_range: Range<MemAddress>,
    }

    impl Default for MachineTestFixture {
        fn default() -> Self {
            let program_offset = (INIT_ZONE_SIZE + PAGE_SIZE) as MemAddress;
            let program = vec![0, 0, 1, 0, 1];
            let mem_readable_range = program_offset..program_offset + program.len() as MemAddress;
            Self {
                program_offset,
                program,
                initial_pc: 0,
                mem_readable_range,
            }
        }
    }

    impl MachineTestFixture {
        fn prepare_vm_builder(&self) -> Result<VMStateBuilder, Box<dyn Error>> {
            VMStateBuilder::builder()
                .with_gas_counter(100)
                .with_reg(7, self.program_offset)
                .with_reg(8, self.program.len() as RegValue)
                .with_reg(9, self.initial_pc)
                .with_mem_data(self.program_offset, &self.program)
        }

        fn prepare_invocation_context(
            &self,
            existing_inner_pvm_count: usize,
        ) -> InvocationContext<MockStateManager> {
            let existing_inner_pvms =
                vec![InnerPVM::new(self.program.clone(), 0); existing_inner_pvm_count];
            InvocationContextBuilder::refine_context_builder()
                .with_inner_pvm_instances(existing_inner_pvms)
                .build()
        }

        fn host_call_result_successful(inner_pvm_id: usize) -> HostCallResult {
            HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: HOSTCALL_BASE_GAS_CHARGE,
                    r7_write: Some(inner_pvm_id as RegValue),
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

    #[test]
    fn test_machine_successful_below_inner_pvm_limit() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = MachineTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(MAX_INNER_PVM_INSTANCES - 1);

        // Check host-call result
        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        let new_inner_pvm_id = MAX_INNER_PVM_INSTANCES - 1;
        assert_eq!(
            res,
            MachineTestFixture::host_call_result_successful(new_inner_pvm_id)
        );

        // Check inner VMs after host-call
        let x = context.get_refine_x().unwrap();
        assert_eq!(x.pvm_instances.len(), MAX_INNER_PVM_INSTANCES);
        let new_inner_pvm = x.pvm_instances.get(&new_inner_pvm_id).unwrap();
        assert_eq!(new_inner_pvm.program_code, fixture.program);
        assert_eq!(new_inner_pvm.pc, fixture.initial_pc);
        Ok(())
    }

    #[test]
    fn test_machine_reuses_smallest_free_id() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = MachineTestFixture::default();
        let machine_vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        // Inner VMs of ids 0, 1, 2 and 3
        let mut context = fixture.prepare_invocation_context(4);

        // Free ids 2 and 0, in that order
        for expunged_inner_pvm_id in [2, 0] {
            let expunge_vm = VMStateBuilder::builder()
                .with_gas_counter(100)
                .with_reg(7, expunged_inner_pvm_id as RegValue)
                .build();
            RefineHostFunction::<MockStateManager>::host_expunge(&expunge_vm, &mut context)?;
        }

        // Each `machine` takes the smallest free id, which is 4 once ids 0 to 3 are held
        for new_inner_pvm_id in [0, 2, 4] {
            let res =
                RefineHostFunction::<MockStateManager>::host_machine(&machine_vm, &mut context)?;
            assert_eq!(
                res,
                MachineTestFixture::host_call_result_successful(new_inner_pvm_id)
            );
        }
        Ok(())
    }

    #[test]
    fn test_machine_full_at_inner_pvm_limit() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = MachineTestFixture::default();
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(MAX_INNER_PVM_INSTANCES);

        // Check host-call result
        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_full());

        // Check inner VMs after host-call
        let x = context.get_refine_x().unwrap();
        assert_eq!(x.pvm_instances.len(), MAX_INNER_PVM_INSTANCES);
        Ok(())
    }

    #[test]
    fn test_machine_full_precedes_mem_not_readable_panic() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = MachineTestFixture::default();
        let vm = fixture.prepare_vm_builder()?.build();
        let mut context = fixture.prepare_invocation_context(MAX_INNER_PVM_INSTANCES);

        // Check host-call result
        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_full());

        // Check inner VMs after host-call
        let x = context.get_refine_x().unwrap();
        assert_eq!(x.pvm_instances.len(), MAX_INNER_PVM_INSTANCES);
        Ok(())
    }
}
