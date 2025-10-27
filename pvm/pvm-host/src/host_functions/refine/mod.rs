use crate::{
    context::InvocationContext,
    error::HostCallError,
    host_functions::{HostCallResult, HostCallReturnCode, InnerPVMResultConstant::*},
    inner_vm::InnerPVM,
    macros::*,
    utils::zero_pad_single_block,
};
use fr_codec::prelude::*;
use fr_common::{
    Hash32, ServiceId, SignedGas, UnsignedGas, HASH_SIZE, MAX_EXPORTS_PER_PACKAGE, SEGMENT_SIZE,
};
use fr_pvm_core::{
    interpreter::Interpreter,
    program::{loader::ProgramLoader, types::program_state::ProgramState},
    state::{
        memory::AccessType,
        state_change::HostCallVMStateChange,
        vm_state::{Registers, VMState},
    },
};
use fr_pvm_types::{
    common::{ExportDataSegment, MemAddress, RegValue},
    constants::{HOSTCALL_BASE_GAS_CHARGE, PAGE_SIZE},
    exit_reason::ExitReason,
};
use fr_state::{provider::HostStateProvider, types::Timeslot};
use std::{marker::PhantomData, sync::Arc};

pub struct RefineHostFunction<S> {
    _phantom: PhantomData<S>,
}
impl<S: HostStateProvider> RefineHostFunction<S> {
    /// Performs a historical preimage lookup for the specified account and hash,
    /// retrieving the preimage data if available.
    ///
    /// This is the only stateful operation in the refinement process and allows auditors to access
    /// states required for execution of the refinement through historical lookups.
    pub async fn host_historical_lookup(
        refine_service_id: ServiceId,
        vm: &VMState,
        context: &mut InvocationContext<S>,
        state_provider: Arc<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: HISTORICAL_LOOKUP");
        check_out_of_gas!(vm.gas_counter);
        let x = get_refine_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(hash_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };

        if !vm.memory.is_address_range_readable(hash_offset, HASH_SIZE) {
            host_call_panic!()
        }
        let Ok(lookup_hash_octets) = vm.memory.read_bytes(hash_offset, HASH_SIZE) else {
            host_call_panic!()
        };
        let lookup_hash = Hash32::decode(&mut lookup_hash_octets.as_slice())?;

        // --- Historical Lookup (Err: NONE)

        let service_id_reg = vm.read_reg(7);
        let service_id = if service_id_reg == u64::MAX
            || state_provider.account_exists(refine_service_id).await?
        {
            refine_service_id
        } else {
            let Ok(service_id_reg) = vm.read_reg_as_service_id(7) else {
                continue_none!()
            };
            if state_provider.account_exists(service_id_reg).await? {
                service_id_reg
            } else {
                continue_none!()
            }
        };

        let Some(preimage) = state_provider
            .lookup_historical_preimage(
                service_id,
                &Timeslot::new(x.invoke_args.package.context.lookup_anchor_timeslot),
                &lookup_hash,
            )
            .await?
        else {
            continue_none!()
        };

        // --- Check Memory Write Access (Err: Panic)

        let preimage_offset = vm
            .read_reg_as_usize(10)
            .unwrap_or(preimage.len())
            .min(preimage.len());
        let min_preimage_len = preimage.len().saturating_sub(preimage_offset);
        let lookup_size = vm
            .read_reg_as_usize(11)
            .unwrap_or(min_preimage_len)
            .min(min_preimage_len);

        let Ok(buf_offset) = vm.read_reg_as_mem_address(9) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_writable(buf_offset, lookup_size) {
            host_call_panic!()
        }

        // --- OK

        tracing::debug!("HISTORICAL_LOOKUP key={lookup_hash} len={lookup_size}");
        continue_with_vm_change!(
            r7: preimage.len(),
            mem_offset: buf_offset,
            mem_data: preimage[preimage_offset..preimage_offset + lookup_size].to_vec()
        )
    }

    /// Appends an entry to the export segments vector using the value loaded from memory.
    /// This export segments vector will be written to the ImportDA after the successful execution
    /// of the refinement process.
    pub fn host_export(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: EXPORT");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        let export_size = vm
            .read_reg_as_usize(8)
            .unwrap_or(SEGMENT_SIZE)
            .min(SEGMENT_SIZE);

        if !vm.memory.is_address_range_readable(offset, export_size) {
            host_call_panic!()
        }
        let Ok(data_segment_octets) = vm.memory.read_bytes(offset, export_size) else {
            host_call_panic!()
        };

        // --- Check Exports Count (Err: FULL)

        let next_export_segments_offset =
            x.export_segments.len() + x.invoke_args.export_segments_offset;
        if next_export_segments_offset >= MAX_EXPORTS_PER_PACKAGE {
            continue_full!()
        }

        // --- OK

        let data_segment: ExportDataSegment =
            zero_pad_single_block::<SEGMENT_SIZE>(data_segment_octets)
                .ok_or(HostCallError::DataSegmentTooLarge)?; // unreachable; export size bounded to `SEGMENT_SIZE`

        x.export_segments.push(data_segment);

        tracing::debug!("EXPORT next_exports_offset={next_export_segments_offset}");
        continue_with_vm_change!(r7: next_export_segments_offset)
    }

    /// Initializes an inner VM with the specified program and the initial program counter.
    ///
    /// Memory of the inner VM is initialized with zero value cells and `Inaccessible` pages.
    pub fn host_machine(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: MACHINE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Read from Memory (Err: Panic)

        let Ok(program_offset) = vm.read_reg_as_mem_address(7) else {
            host_call_panic!()
        };
        let Ok(program_size) = vm.read_reg_as_usize(8) else {
            host_call_panic!()
        };

        if !vm
            .memory
            .is_address_range_readable(program_offset, program_size)
        {
            host_call_panic!()
        }
        let Ok(program) = vm.memory.read_bytes(program_offset, program_size) else {
            host_call_panic!()
        };

        // --- Check Program Format (Err: HUH)

        // Validate the program blob can be `deblob`ed properly
        if ProgramLoader::deblob_program_code(&program).is_err() {
            continue_huh!()
        }

        // --- OK

        let initial_pc = vm.read_reg(9);
        let inner_vm = InnerPVM::new(program, initial_pc);
        let inner_vm_id = x.add_pvm_instance(inner_vm); // n

        tracing::debug!("MACHINE instance_id={inner_vm_id}");
        continue_with_vm_change!(r7: inner_vm_id)
    }

    /// Peeks data from the inner VM memory and copies it to the external host VM memory.
    ///
    /// `HostVM` `<--(peek)--` `InnerVM`
    pub fn host_peek(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: PEEK");
        check_out_of_gas!(vm.gas_counter);
        let x = get_refine_x!(context);

        // --- Check HostVM Memory Write Access (Err: Panic)

        let Ok(memory_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        let Ok(data_size) = vm.read_reg_as_usize(10) else {
            host_call_panic!()
        };

        if !vm
            .memory
            .is_address_range_writable(memory_offset, data_size)
        {
            host_call_panic!()
        }

        // --- Check InnerVM Id (Err: WHO)

        let Ok(inner_vm_id) = vm.read_reg_as_usize(7) else {
            continue_who!()
        };
        let Some(inner_memory) = x.get_inner_vm_memory(inner_vm_id) else {
            continue_who!()
        };

        // --- Check InnerVM Memory Read Access (Err: OOB)

        let Ok(inner_memory_offset) = vm.read_reg_as_mem_address(9) else {
            continue_oob!()
        };
        if !inner_memory.is_address_range_readable(inner_memory_offset, data_size) {
            continue_oob!()
        }
        let Ok(data) = inner_memory.read_bytes(inner_memory_offset, data_size) else {
            continue_oob!()
        };

        // --- OK

        continue_with_vm_change!(r7: HostCallReturnCode::OK, mem_offset: memory_offset, mem_data: data)
    }

    /// Pokes data into the inner VM memory from the external host VM memory.
    ///
    /// `HostVM` `--(poke)-->` `InnerVM`
    pub fn host_poke(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: POKE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Check HostVM Memory Read Access (Err: Panic)

        let Ok(memory_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        let Ok(data_size) = vm.read_reg_as_usize(10) else {
            host_call_panic!()
        };
        if !vm
            .memory
            .is_address_range_readable(memory_offset, data_size)
        {
            host_call_panic!()
        }
        let Ok(data) = vm.memory.read_bytes(memory_offset, data_size) else {
            host_call_panic!()
        };

        // --- Check InnerVM Id (Err: WHO)

        let Ok(inner_vm_id) = vm.read_reg_as_usize(7) else {
            continue_who!()
        };
        let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) else {
            continue_who!()
        };

        // --- Check InnerVM Memory Write Access (Err: OOB)

        let Ok(inner_memory_offset) = vm.read_reg_as_mem_address(9) else {
            continue_oob!()
        };
        if !inner_memory_mut.is_address_range_writable(inner_memory_offset, data_size) {
            continue_oob!()
        }

        // --- OK (with OOB check)

        let Ok(_) = inner_memory_mut.write_bytes(inner_memory_offset as MemAddress, &data) else {
            continue_oob!()
        };
        continue_ok!()
    }

    /// Allocates or deallocates a range of inner VM memory pages.
    /// This is done by updating accessibility of the pages. Optionally, values can be cleared.
    pub fn host_pages(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: PAGES");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Check InnerVM Id (Err: WHO)

        let Ok(inner_vm_id) = vm.read_reg_as_usize(7) else {
            continue_who!()
        };
        let Some(inner_memory_mut) = x.get_mut_inner_vm_memory(inner_vm_id) else {
            continue_who!()
        };

        // --- Check InnerVM Memory State (Err: HUH)

        let Ok(inner_memory_page_offset) = vm.read_reg_as_usize(8) else {
            continue_huh!()
        };
        let Ok(pages_count) = vm.read_reg_as_usize(9) else {
            continue_huh!()
        };
        let Ok(mode) = vm.read_reg_as_usize(10) else {
            continue_huh!()
        };

        if mode > 4
            || inner_memory_page_offset < 16
            || inner_memory_page_offset + pages_count >= (1 << 32) / PAGE_SIZE
        {
            continue_huh!()
        }

        // cannot allocate new pages without clearing values
        let page_start = inner_memory_page_offset;
        let page_end = inner_memory_page_offset + pages_count;
        if mode > 2 && !inner_memory_mut.is_page_range_readable(page_start..page_end) {
            continue_huh!()
        }

        // --- OK (with HUH checks)

        // conditionally clear values
        if mode < 3 {
            let address_offset = (inner_memory_page_offset * PAGE_SIZE) as MemAddress;
            let data_size = pages_count * PAGE_SIZE;
            let Ok(_) = inner_memory_mut.write_bytes(address_offset, &vec![0u8; data_size]) else {
                continue_huh!()
            };
        }

        // set access types
        let access_type = match mode {
            0 => AccessType::Inaccessible,
            1 | 3 => AccessType::ReadOnly,
            2 | 4 => AccessType::ReadWrite,
            _ => continue_huh!(),
        };
        let Ok(_) = inner_memory_mut.set_page_range_access(page_start..page_end, access_type)
        else {
            continue_huh!()
        };

        tracing::debug!("PAGES instance_id={inner_vm_id} mode={mode} pages={page_start}..{page_end} access={access_type:?}");
        continue_ok!()
    }

    /// Invokes the inner VM with its program using the PVM general invocation function `Ψ`.
    ///
    /// The gas limit and initial register values for the inner VM are read from the memory of the host VM.
    /// Upon completion, the posterior state (e.g., gas counter, memory, registers) of the inner VM is
    /// written back to the memory of the host VM, while the final state of the inner VM's memory
    /// is preserved within the inner VM.
    pub fn host_invoke(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: INVOKE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Check HostVM Memory Write Access and Read Gas Limit & Registers (Err: Panic)

        let Ok(memory_offset) = vm.read_reg_as_mem_address(8) else {
            host_call_panic!()
        };
        if !vm.memory.is_address_range_writable(memory_offset, 112) {
            host_call_panic!()
        }
        let Ok(gas_limit_octets) = vm.memory.read_bytes(memory_offset, 8) else {
            host_call_panic!()
        };

        let gas_limit = UnsignedGas::decode_fixed(&mut gas_limit_octets.as_slice(), 8)?;
        let mut regs = Registers::default();
        for (i, reg) in regs.iter_mut().enumerate() {
            let Ok(read_val) = vm
                .memory
                .read_bytes(memory_offset + 8 + 8 * i as MemAddress, 8)
            else {
                host_call_panic!()
            };
            *reg = RegValue::decode_fixed(&mut read_val.as_slice(), 8)?;
        }

        // --- Check InnerVM Id (Err: WHO)

        let Ok(inner_vm_id) = vm.read_reg_as_usize(7) else {
            continue_who!()
        };
        let Some(inner_vm_mut) = x.pvm_instances.get_mut(&inner_vm_id) else {
            continue_who!()
        };

        // --- PVM Invocation

        // Construct a new `VMState` and `ProgramState` for the general invocation function.
        let mut inner_vm_state_copy = VMState {
            regs,
            memory: inner_vm_mut.memory.clone(),
            pc: inner_vm_mut.pc,
            gas_counter: gas_limit
                .try_into()
                .map_err(|_| HostCallError::GasLimitOverflow(gas_limit))?,
        };
        let inner_vm_program_code = &inner_vm_mut.program_code;
        let mut inner_vm_program_state = ProgramState::default();

        let inner_vm_exit_reason = Interpreter::invoke_general(
            &mut inner_vm_state_copy,
            &mut inner_vm_program_state,
            inner_vm_program_code,
        )?;

        // Apply the mutation of the `VMState` to the InnerVM state of the refine context
        inner_vm_mut.pc = inner_vm_state_copy.pc;
        inner_vm_mut.memory = inner_vm_state_copy.memory;

        // 112-byte mem write
        let mut host_buf = vec![];
        (inner_vm_state_copy.gas_counter as UnsignedGas).encode_to_fixed(&mut host_buf, 8)?;
        for reg in inner_vm_state_copy.regs {
            reg.encode_to_fixed(&mut host_buf, 8)?;
        }

        // --- OK (Handle PVM Exit Reasons: HOST, FAULT, OOG, PANIC, HALT)

        tracing::debug!("INVOKE instance_id={inner_vm_id} exit_reason={inner_vm_exit_reason:?}");
        match inner_vm_exit_reason {
            ExitReason::HostCall(host_call_type) => {
                inner_vm_mut.pc += 1;
                continue_with_vm_change!(
                    r7: HOST,
                    r8: host_call_type.clone(),
                    mem_offset: memory_offset,
                    mem_data: host_buf
                )
            }
            ExitReason::PageFault(address) => {
                continue_with_vm_change!(
                    r7: FAULT,
                    r8: address,
                    mem_offset: memory_offset,
                    mem_data: host_buf
                )
            }
            ExitReason::OutOfGas => {
                continue_with_vm_change!(
                    r7: OOG,
                    mem_offset: memory_offset,
                    mem_data: host_buf
                )
            }
            ExitReason::Panic => {
                continue_with_vm_change!(
                    r7: PANIC,
                    mem_offset: memory_offset,
                    mem_data: host_buf
                )
            }
            ExitReason::RegularHalt => {
                continue_with_vm_change!(
                    r7: HALT,
                    mem_offset: memory_offset,
                    mem_data: host_buf
                )
            }

            _ => Err(HostCallError::InvalidExitReason),
        }
    }

    /// Removes an inner VM instance from the refine context and returns its final pc.
    pub fn host_expunge(
        vm: &VMState,
        context: &mut InvocationContext<S>,
    ) -> Result<HostCallResult, HostCallError> {
        tracing::debug!("Hostcall invoked: EXPUNGE");
        check_out_of_gas!(vm.gas_counter);
        let x = get_mut_refine_x!(context);

        // --- Check InnerVM Id (Err: WHO)

        let Ok(inner_vm_id) = vm.read_reg_as_usize(7) else {
            continue_who!()
        };
        let Some(inner_vm) = x.pvm_instances.get(&inner_vm_id) else {
            continue_who!()
        };

        // --- OK

        let final_pc = inner_vm.pc;
        x.remove_pvm_instance(inner_vm_id);

        tracing::debug!("EXPUNGE instance_id={inner_vm_id}");
        continue_with_vm_change!(r7: final_pc)
    }
}
