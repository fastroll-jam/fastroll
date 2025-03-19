use rjam_common::{ServiceId, SignedGas, UnsignedGas};
use rjam_pvm_core::{
    constants::{INIT_INPUT_SIZE, INIT_ZONE_SIZE, MEMORY_SIZE, PAGE_SIZE},
    interpreter::Interpreter,
    program::decoder::{FormattedProgram, ProgramDecoder, ProgramState},
    state::{
        memory::{AccessType, MemAddress, Memory},
        VMState,
    },
    types::{
        common::{ExitReason, RegValue},
        error::{
            HostCallError::{InvalidExitReason, InvalidMemoryWrite},
            PVMError,
            VMCoreError::*,
        },
        hostcall::HostCallType,
    },
    utils::VMUtils,
};
use rjam_pvm_host::{
    context::InvocationContext,
    host_functions::{HostCallResult, HostCallVMStateChange, HostFunction, MemWrite},
};
use rjam_state::manager::StateManager;
use std::sync::Arc;

#[allow(dead_code)]
enum ExecutionResult {
    Complete(ExitReason),
    HostCall(HostCallType),
}

pub enum CommonInvocationResult {
    /// Regular halt with return value
    Result(Vec<u8>),
    /// Regular halt with no return value
    ResultUnavailable,
    /// Out of gas
    OutOfGas(ExitReason),
    /// Panic
    Panic(ExitReason),
}

struct ExtendedInvocationResult {
    exit_reason: ExitReason,
}

/// Main stateful PVM struct
#[derive(Default)]
pub struct PVM {
    /// The mutable VM state
    pub state: VMState,
    /// Equivalent to `code` of `FormattedProgram`
    pub program_blob: Vec<u8>,
    /// The static program state initialized in the general invocation `Ψ`
    pub program_state: ProgramState,
}

impl PVM {
    //
    // VM states initialization
    //

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` of the GP
    fn new_with_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, PVMError> {
        let mut pvm = Self::default();

        // Check argument data size limit
        if args.len() > INIT_INPUT_SIZE {
            return Err(PVMError::VMCoreError(ProgramArgsSizeLimitExceeded));
        }

        // Decode program and check program size limit
        let formatted_program = ProgramDecoder::decode_standard_program(standard_program)?;
        if !formatted_program.is_program_size_valid() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        pvm.setup_memory_layout(&formatted_program, args)?;
        pvm.initialize_registers(args.len());
        pvm.program_blob = formatted_program.code;

        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), PVMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only static data (o)
        let o_start = INIT_ZONE_SIZE as MemAddress; // Z_Z
        let o_padding_end = o_start + VMUtils::page_align(fp.static_size as usize) as MemAddress;
        memory.set_address_range_access(o_start..o_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(o_start, &fp.static_data)?;

        // Read-write heap data (w)
        let w_start =
            (2 * INIT_ZONE_SIZE + VMUtils::zone_align(fp.static_size as usize)) as MemAddress;
        let w_padding_end = w_start
            + VMUtils::page_align(fp.heap_size as usize) as MemAddress
            + fp.extra_heap_pages as MemAddress * PAGE_SIZE as MemAddress;
        memory.set_address_range_access(w_start..w_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(w_start, &fp.heap_data)?;
        memory.heap_start = w_start;

        // Stack (s)
        let s_start = ((1 << 32)
            - 2 * INIT_ZONE_SIZE
            - INIT_INPUT_SIZE
            - VMUtils::page_align(fp.stack_size as usize)) as MemAddress;
        let s_end = ((1 << 32) - 2 * INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        memory.set_address_range_access(s_start..s_end, AccessType::ReadWrite)?;

        // Arguments (a)
        let a_start = ((1 << 32) - INIT_ZONE_SIZE - INIT_INPUT_SIZE) as MemAddress;
        let a_padding_end = a_start + VMUtils::page_align(args.len()) as MemAddress;
        memory.set_address_range_access(a_start..a_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(a_start, args)?;

        // Other addresses are inaccessible
        memory.set_address_range_access(0..o_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(o_padding_end..w_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(w_padding_end..s_start, AccessType::Inaccessible)?;
        memory.set_address_range_access(s_end..a_start, AccessType::Inaccessible)?;
        memory
            .set_address_range_access(a_padding_end..MemAddress::MAX, AccessType::Inaccessible)?;

        self.state.memory = memory;
        Ok(())
    }

    fn initialize_registers(&mut self, args_len: usize) {
        self.state.regs[0].value = (1 << 32) - (1 << 16);
        self.state.regs[1].value = (1 << 32) - (2 * INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[7].value = (1 << 32) - (INIT_ZONE_SIZE + INIT_INPUT_SIZE) as RegValue;
        self.state.regs[8].value = args_len as RegValue;
    }

    //
    // VM state read functions
    //

    /// Read a byte from memory
    #[allow(dead_code)]
    fn read_memory_byte(&self, address: MemAddress) -> Result<u8, PVMError> {
        Ok(self.state.memory.read_byte(address)?)
    }

    /// Read a specified number of bytes from memory starting at the given address
    fn read_memory_bytes(&self, address: MemAddress, length: usize) -> Result<Vec<u8>, PVMError> {
        Ok(self.state.memory.read_bytes(address, length)?)
    }

    //
    // VM state mutation function
    //

    fn apply_host_call_state_change(
        &mut self,
        change: &HostCallVMStateChange,
    ) -> Result<SignedGas, PVMError> {
        // Apply register changes (register index 7 & 8)
        if let Some(r7) = change.r7_write {
            self.state.regs[7].value = r7;
        }
        if let Some(r8) = change.r8_write {
            self.state.regs[8].value = r8;
        }

        // Apply memory change
        if let Some(MemWrite {
            buf_offset,
            write_len,
            write_data,
        }) = change.memory_write.clone()
        {
            if write_len as usize > write_data.len() {
                return Err(PVMError::HostCallError(InvalidMemoryWrite));
            }
            for (offset, &byte) in write_data.iter().take(write_len as usize).enumerate() {
                self.state
                    .memory
                    .write_byte(buf_offset.wrapping_add(offset as u32), byte)?;
            }
        }

        // Check gas counter and apply gas change
        let post_gas = Interpreter::apply_gas_cost(&mut self.state, change.gas_charge)?;
        Ok(post_gas)
    }

    //
    // Common PVM invocation functions
    //

    /// Invokes the PVM with standard program blob and arguments.
    /// This works as a common interface for the four PVM invocation entry-points.
    ///
    /// # Input Program
    /// This function accepts a standard program blob as input, which is then decoded into a
    /// `FormattedProgram` type. The decoding process extracts information about the memory layout
    /// necessary for initialization. Subsequently, the code section of the `FormattedProgram`
    /// is loaded as an immutable state within the `PVM`. This immutable state allows the program code
    /// to be utilized during the execution of the `invoke_extended` and `invoke_general` functions.
    ///
    /// Represents `Ψ_M` of the GP.
    pub async fn invoke_with_args(
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        standard_program: &[u8],
        pc: RegValue,
        gas: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext,
    ) -> Result<CommonInvocationResult, PVMError> {
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let mut pvm = match Self::new_with_standard_program(standard_program, args) {
            Ok(pvm) => pvm,
            Err(_) => return Ok(CommonInvocationResult::Panic(ExitReason::Panic)),
        };
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas;

        let result = pvm
            .invoke_extended(state_manager, service_id, context)
            .await?;

        match result.exit_reason {
            ExitReason::OutOfGas => Ok(CommonInvocationResult::OutOfGas(ExitReason::OutOfGas)),
            ExitReason::RegularHalt => {
                let start_address = pvm.state.read_reg_as_mem_address(10)?;
                let data_len = pvm.state.read_reg(11) as usize;
                if !pvm
                    .state
                    .memory
                    .is_address_range_readable(start_address, data_len)?
                {
                    return Ok(CommonInvocationResult::ResultUnavailable);
                }

                let bytes = pvm.read_memory_bytes(start_address, data_len)?;
                Ok(CommonInvocationResult::Result(bytes))
            }
            _ => Ok(CommonInvocationResult::Panic(ExitReason::Panic)),
        }
    }

    /// Invokes the PVM general functions including host calls with arguments injected by the `Ψ_M`
    /// common invocation function.
    ///
    /// # Input Program
    /// This function utilizes the program component of the `PVM` state.
    ///
    /// Represents `Ψ_H` of the GP.
    async fn invoke_extended(
        &mut self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        context: &mut InvocationContext,
    ) -> Result<ExtendedInvocationResult, PVMError> {
        loop {
            let exit_reason = Interpreter::invoke_general(
                &mut self.state,
                &mut self.program_state,
                &self.program_blob,
            )?;

            let host_call_result = match exit_reason {
                ExitReason::HostCall(h) => {
                    self.execute_host_function(state_manager.clone(), service_id, context, &h)
                        .await?
                }
                _ => return Ok(ExtendedInvocationResult { exit_reason }),
            };

            match host_call_result.exit_reason {
                exit_reason @ ExitReason::PageFault(_) => {
                    return Ok(ExtendedInvocationResult { exit_reason });
                }
                ExitReason::Continue => {
                    // update the vm states
                    let post_gas =
                        self.apply_host_call_state_change(&host_call_result.vm_change)?;
                    if post_gas < 0 {
                        // Actually this should never happen, since gas usage is inspected prior to
                        // the host function execution and the `HostCallResult` with `ExitReason::OutOfGas`
                        // should be returned if post gas counter could be less than zero.
                        return Ok(ExtendedInvocationResult {
                            exit_reason: ExitReason::OutOfGas,
                        });
                    }
                }
                exit_reason @ (ExitReason::Panic
                | ExitReason::RegularHalt
                | ExitReason::OutOfGas) => {
                    self.apply_host_call_state_change(&host_call_result.vm_change)?;
                    return Ok(ExtendedInvocationResult { exit_reason });
                }
                _ => return Err(PVMError::HostCallError(InvalidExitReason)),
            }
        }
    }

    async fn execute_host_function(
        &self,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        context: &mut InvocationContext,
        h: &HostCallType,
    ) -> Result<HostCallResult, PVMError> {
        let result = match h {
            //
            // General Functions
            //
            HostCallType::GAS => HostFunction::host_gas(&self.state)?,
            HostCallType::LOOKUP => {
                HostFunction::host_lookup(service_id, &self.state, state_manager, context).await?
            }
            HostCallType::READ => {
                HostFunction::host_read(service_id, &self.state, state_manager, context).await?
            }
            HostCallType::WRITE => {
                HostFunction::host_write(service_id, &self.state, state_manager, context).await?
            }
            HostCallType::INFO => {
                HostFunction::host_info(service_id, &self.state, state_manager, context).await?
            }
            //
            // Accumulate Functions
            //
            HostCallType::BLESS => HostFunction::host_bless(&self.state, context)?,
            HostCallType::ASSIGN => HostFunction::host_assign(&self.state, context)?,
            HostCallType::DESIGNATE => HostFunction::host_designate(&self.state, context)?,
            HostCallType::CHECKPOINT => HostFunction::host_checkpoint(&self.state, context)?,
            HostCallType::NEW => {
                HostFunction::host_new(&self.state, state_manager, context).await?
            }
            HostCallType::UPGRADE => {
                HostFunction::host_upgrade(&self.state, state_manager, context).await?
            }
            HostCallType::TRANSFER => {
                HostFunction::host_transfer(&self.state, state_manager, context).await?
            }
            HostCallType::EJECT => {
                HostFunction::host_eject(&self.state, state_manager, context).await?
            }
            HostCallType::QUERY => {
                HostFunction::host_query(&self.state, state_manager, context).await?
            }
            HostCallType::SOLICIT => {
                HostFunction::host_solicit(&self.state, state_manager, context).await?
            }
            HostCallType::FORGET => {
                HostFunction::host_forget(&self.state, state_manager, context).await?
            }
            HostCallType::YIELD => HostFunction::host_yield(&self.state, context).await?,
            //
            // Refine Functions
            //
            HostCallType::HISTORICAL_LOOKUP => {
                HostFunction::host_historical_lookup(
                    service_id,
                    &self.state,
                    context,
                    state_manager,
                )
                .await?
            }
            HostCallType::FETCH => HostFunction::host_fetch(&self.state, context)?,
            HostCallType::EXPORT => HostFunction::host_export(&self.state, context)?,
            HostCallType::MACHINE => HostFunction::host_machine(&self.state, context)?,
            HostCallType::PEEK => HostFunction::host_peek(&self.state, context)?,
            HostCallType::POKE => HostFunction::host_poke(&self.state, context)?,
            HostCallType::ZERO => HostFunction::host_zero(&self.state, context)?,
            HostCallType::VOID => HostFunction::host_void(&self.state, context)?,
            HostCallType::INVOKE => HostFunction::host_invoke(&self.state, context)?,
            HostCallType::EXPUNGE => HostFunction::host_expunge(&self.state, context)?,
        };

        Ok(result)
    }
}
