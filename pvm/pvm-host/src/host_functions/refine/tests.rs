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
            Self::new(vec![0, 0, 1, 0, 1], 0)
        }
    }

    impl MachineTestFixture {
        fn new(program: Vec<u8>, initial_pc: RegValue) -> Self {
            let program_offset = (INIT_ZONE_SIZE + PAGE_SIZE) as MemAddress;
            let mem_readable_range = program_offset..program_offset + program.len() as MemAddress;
            Self {
                program_offset,
                program,
                initial_pc,
                mem_readable_range,
            }
        }

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

    #[test]
    fn test_machine_huh_on_initial_pc_without_instruction() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        // The single `trap` is at 0, so 1 is past the instruction data
        let fixture = MachineTestFixture::new(vec![0, 0, 1, 0, 1], 1);
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(0);

        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_huh());
        assert!(context.get_refine_x().unwrap().pvm_instances.is_empty());
        Ok(())
    }

    #[test]
    fn test_machine_huh_on_invalid_instruction_sequence() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        // A single `unlikely`, which does not end a basic block
        let fixture = MachineTestFixture::new(vec![0, 0, 1, 2, 1], 0);
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(0);

        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_huh());
        assert!(context.get_refine_x().unwrap().pvm_instances.is_empty());
        Ok(())
    }

    #[test]
    fn test_machine_huh_on_initial_pc_at_argument_octet() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        // `trap` with an argument octet, so index 1 is inside `c` but not an opcode
        let fixture = MachineTestFixture::new(vec![0, 0, 2, 0, 0, 1], 1);
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(0);

        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_huh());
        Ok(())
    }

    #[test]
    fn test_machine_full_precedes_huh() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let fixture = MachineTestFixture::new(vec![0, 0, 1, 0, 1], 1);
        let vm = fixture
            .prepare_vm_builder()?
            .with_mem_readable_range(fixture.mem_readable_range.clone())?
            .build();
        let mut context = fixture.prepare_invocation_context(MAX_INNER_PVM_INSTANCES);

        let res = RefineHostFunction::<MockStateManager>::host_machine(&vm, &mut context)?;
        assert_eq!(res, MachineTestFixture::host_call_result_full());
        Ok(())
    }
}

mod invoke_tests {
    use super::*;
    use crate::host_functions::InnerPVMResultConstant;
    use fr_common::UnsignedGas;
    use fr_pvm_core::{
        program::{loader::ProgramLoader, types::program_state::ProgramState},
        state::memory::{AccessType, Memory},
    };

    /// Offset of the 112-octet `invoke` argument, holding the encoded gas limit and registers
    const INVOKE_ARGUMENT_OFFSET: MemAddress = (INIT_ZONE_SIZE + PAGE_SIZE) as MemAddress;

    /// A program whose only basic block is `ecalli 0` followed by `trap`.
    /// `|j| = 0`, `z = 0`, `|c| = 3`, `c = [ecalli, 0, trap]`, `k = 0b101`
    const ECALLI_THEN_TRAP: [u8; 7] = [0, 0, 3, 10, 0, 0, 0b101];

    /// Page that `LOAD_THEN_TRAP` reads, unmapped in a new inner VM
    const LOADED_PAGE_ADDRESS: MemAddress = 0x20000;

    /// A program whose only basic block is `load_u8 r0, 0x20000` followed by `trap`.
    /// `|c| = 7`, `c = [load_u8, r0, E_4(0x20000), trap]`, `k = 0b1000001`
    const LOAD_THEN_TRAP: [u8; 11] = [0, 0, 7, 52, 0, 0, 0, 2, 0, 0, 0b1000001];

    fn inner_pvm(program_code: &[u8]) -> Result<InnerPVM, Box<dyn Error>> {
        Ok(InnerPVM::new(program_code.to_vec(), 0))
    }

    /// Returns the gas cost of the block that starts at 0.
    fn first_block_gas_cost(program_code: &[u8]) -> Result<UnsignedGas, Box<dyn Error>> {
        let mut program_state = ProgramState::default();
        ProgramLoader::load_program(program_code, &mut program_state)?;
        Ok(program_state
            .basic_block_gas_cost_at(0)
            .ok_or("no block at 0")?)
    }

    fn context_with_inner_pvm(
        program_code: &[u8],
    ) -> Result<InvocationContext<MockStateManager>, Box<dyn Error>> {
        Ok(InvocationContextBuilder::refine_context_builder()
            .with_inner_pvm_instances(vec![inner_pvm(program_code)?])
            .build())
    }

    fn inner_pvm_0(context: &mut InvocationContext<MockStateManager>) -> &InnerPVM {
        context
            .get_refine_x()
            .unwrap()
            .pvm_instances
            .get(&0)
            .unwrap()
    }

    fn inner_pvm_0_mut(context: &mut InvocationContext<MockStateManager>) -> &mut InnerPVM {
        context
            .get_mut_refine_x()
            .unwrap()
            .pvm_instances
            .get_mut(&0)
            .unwrap()
    }

    /// Runs `invoke` on inner VM 0 with `gas_limit` and zero registers, and returns the result code in `r7` and the gas left in the inner VM.
    fn invoke(
        context: &mut InvocationContext<MockStateManager>,
        gas_limit: UnsignedGas,
    ) -> Result<(RegValue, UnsignedGas), Box<dyn Error>> {
        let mut invoke_argument = gas_limit.to_le_bytes().to_vec();
        invoke_argument.resize(112, 0);
        let vm = VMStateBuilder::builder()
            .with_gas_counter(100)
            .with_reg(7, 0u64)
            .with_reg(8, INVOKE_ARGUMENT_OFFSET)
            .with_mem_data(INVOKE_ARGUMENT_OFFSET, &invoke_argument)?
            .with_mem_writable_range(INVOKE_ARGUMENT_OFFSET..INVOKE_ARGUMENT_OFFSET + 112)?
            .build();
        let res = RefineHostFunction::<MockStateManager>::host_invoke(&vm, context)?;
        let result_code = res
            .vm_change
            .r7_write
            .ok_or("invoke wrote no result code")?;
        let memory_write = res
            .vm_change
            .memory_write
            .as_ref()
            .ok_or("invoke wrote no result")?;
        let posterior_gas_limit =
            UnsignedGas::from_le_bytes(memory_write.write_data.as_slice()[..8].try_into()?);
        Ok((result_code, posterior_gas_limit))
    }

    #[test]
    fn test_invoke_keeps_gas_charged_flag_across_host_call() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let block_gas_cost = first_block_gas_cost(&ECALLI_THEN_TRAP)?;
        let mut context = context_with_inner_pvm(&ECALLI_THEN_TRAP)?;

        // The first `invoke` charges the block and stops at `ecalli`
        let (result_code, gas_limit) = invoke(&mut context, 1000)?;
        assert_eq!(result_code, InnerPVMResultConstant::HOST as RegValue);
        assert_eq!(gas_limit, 1000 - block_gas_cost);
        assert_eq!(inner_pvm_0(&mut context).pc, 2);
        assert!(inner_pvm_0(&mut context).is_basic_block_gas_charged);

        // Resuming at `trap` in the same block charges nothing, and the panic clears the flag (GP #588)
        let (result_code, gas_limit_after_panic) = invoke(&mut context, gas_limit)?;
        assert_eq!(result_code, InnerPVMResultConstant::PANIC as RegValue);
        assert_eq!(gas_limit_after_panic, gas_limit);
        assert_eq!(inner_pvm_0(&mut context).pc, 0);
        assert!(!inner_pvm_0(&mut context).is_basic_block_gas_charged);
        Ok(())
    }

    #[test]
    fn test_invoke_keeps_gas_charged_flag_across_page_fault() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let block_gas_cost = first_block_gas_cost(&LOAD_THEN_TRAP)?;
        let mut context = context_with_inner_pvm(&LOAD_THEN_TRAP)?;
        // A new inner VM has an empty `Memory`, so give it room for the loaded page
        inner_pvm_0_mut(&mut context).memory =
            Memory::new(LOADED_PAGE_ADDRESS as usize + PAGE_SIZE, PAGE_SIZE);

        // The block is charged before `load_u8` faults on the unmapped page
        let (result_code, gas_limit) = invoke(&mut context, 1000)?;
        assert_eq!(result_code, InnerPVMResultConstant::FAULT as RegValue);
        assert_eq!(gas_limit, 1000 - block_gas_cost);
        assert_eq!(inner_pvm_0(&mut context).pc, 0);
        assert!(inner_pvm_0(&mut context).is_basic_block_gas_charged);

        // Mapping the page and resuming at `load_u8` charges nothing again
        inner_pvm_0_mut(&mut context)
            .memory
            .set_address_range_access(
                LOADED_PAGE_ADDRESS..LOADED_PAGE_ADDRESS + PAGE_SIZE as MemAddress,
                AccessType::ReadWrite,
            )?;
        let (result_code, gas_limit_after_panic) = invoke(&mut context, gas_limit)?;
        assert_eq!(result_code, InnerPVMResultConstant::PANIC as RegValue);
        assert_eq!(gas_limit_after_panic, gas_limit);
        Ok(())
    }

    #[test]
    fn test_invoke_charges_block_only_with_enough_gas() -> Result<(), Box<dyn Error>> {
        setup_tracing();
        let block_gas_cost = first_block_gas_cost(&ECALLI_THEN_TRAP)?;
        let mut context = context_with_inner_pvm(&ECALLI_THEN_TRAP)?;

        // One gas short of the block cost leaves the gas limit, pc and flag unchanged
        let (result_code, gas_limit) = invoke(&mut context, block_gas_cost - 1)?;
        assert_eq!(result_code, InnerPVMResultConstant::OOG as RegValue);
        assert_eq!(gas_limit, block_gas_cost - 1);
        assert_eq!(inner_pvm_0(&mut context).pc, 0);
        assert!(!inner_pvm_0(&mut context).is_basic_block_gas_charged);

        // Exactly the block cost runs the block up to `ecalli`
        let (result_code, gas_limit) = invoke(&mut context, block_gas_cost)?;
        assert_eq!(result_code, InnerPVMResultConstant::HOST as RegValue);
        assert_eq!(gas_limit, 0);
        Ok(())
    }
}
