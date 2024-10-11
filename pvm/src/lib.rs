use rjam_common::{Address, Octets, UnsignedGas};
use rjam_host_interface::{
    contexts::InvocationContext,
    host_functions::{HostCallResult, HostCallVMStateChange, HostFunction},
};
use rjam_pvm_core::{
    constants::{
        HOST_CALL_INPUT_REGISTERS_COUNT, INPUT_SIZE, MEMORY_SIZE, PAGE_SIZE, SEGMENT_SIZE,
    },
    core::{PVMCore, Program, VMState},
    instructions::program_decoder::{FormattedProgram, ProgramDecoder},
    state::{
        memory::{AccessType, MemAddress, Memory},
        register::Register,
    },
    types::{
        common::ExitReason,
        error::{
            PVMError,
            VMCoreError::{InvalidHostCallType, InvalidProgram, OutOfGas},
        },
        hostcall::HostCallType,
    },
    utils::VMUtils,
};
use rjam_state::StateManager;

enum ExecutionResult {
    Complete(ExitReason),
    HostCall(HostCallType),
}

// TODO: check the GP - `InvocationContext` elided for `Result` and `ResultUnavailable`
pub enum CommonInvocationResult {
    OutOfGas(ExitReason),
    Result((UnsignedGas, Octets)), // (posterior_gas, return_value)
    ResultUnavailable((UnsignedGas, Octets)), // (posterior_gas, [])
    Failure(ExitReason),           // panic
}

// TODO: add other posterior VM states?
struct ExtendedInvocationResult {
    exit_reason: ExitReason,
}

/// Main stateful PVM struct
#[derive(Default)]
pub struct PVM {
    state: VMState,
    program: Program,
}

impl PVM {
    //
    // VM states initialization
    //

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` of the GP
    fn new_from_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, PVMError> {
        let mut pvm = PVM::default();

        // decode program and check validity
        let formatted_program = ProgramDecoder::decode_standard_program(standard_program)?;
        if !formatted_program.check_size_limit() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }

        pvm.setup_memory_layout(&formatted_program, &args)?;
        pvm.initialize_registers(args.len());
        pvm.program.program_code = formatted_program.code;

        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), PVMError> {
        let mut memory = Memory::new(MEMORY_SIZE, PAGE_SIZE);

        // Program-specific read-only data area (o)
        let o_start = SEGMENT_SIZE; // Z_Q
        let o_end = o_start + fp.read_only_len as usize;
        memory.set_range(o_start, &fp.read_only_data[..], AccessType::ReadOnly);
        memory.set_access_range(
            o_end,
            SEGMENT_SIZE + VMUtils::p(fp.read_only_len as usize),
            AccessType::ReadOnly,
        );

        // Read-write (heap) data (w)
        let w_start = 2 * SEGMENT_SIZE + VMUtils::q(fp.read_only_len as usize);
        memory.heap_start = w_start as MemAddress;
        let w_end = w_start + fp.read_write_len as usize;
        memory.set_range(w_start, &fp.read_write_data[..], AccessType::ReadWrite);
        let heap_end = w_end + VMUtils::p(fp.read_write_len as usize) - fp.read_write_len as usize
            + fp.extra_heap_pages as usize * PAGE_SIZE;
        memory.set_access_range(w_end, heap_end, AccessType::ReadWrite);

        // Stack (s)
        let stack_start =
            (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE - VMUtils::p(fp.stack_size as usize);
        let stack_end = (1 << 32) - 2 * SEGMENT_SIZE - INPUT_SIZE;
        memory.set_access_range(stack_start, stack_end, AccessType::ReadWrite);

        // Arguments
        let args_start = (1 << 32) - SEGMENT_SIZE - INPUT_SIZE;
        let args_end = args_start + args.len();
        memory.set_range(args_start, &args[..], AccessType::ReadOnly);
        memory.set_access_range(
            args_end,
            (1 << 32) - SEGMENT_SIZE - INPUT_SIZE + VMUtils::p(args.len()),
            AccessType::ReadOnly,
        );

        // Other addresses are inaccessible
        memory.set_access_range(0, SEGMENT_SIZE, AccessType::Inaccessible);
        memory.set_access_range(heap_end, stack_start, AccessType::Inaccessible);
        memory.set_access_range(stack_end, args_start, AccessType::Inaccessible);

        self.state.memory = memory;
        Ok(())
    }

    fn initialize_registers(&mut self, args_len: usize) {
        self.state.registers[0].value = u32::MAX - (1 << 16) + 1;
        self.state.registers[1].value = u32::MAX - (2 * SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[7].value = u32::MAX - (SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[8].value = args_len as u32;
    }

    //
    // PVM helper function
    //

    /// Get a reference to registers for host call function arguments
    pub fn get_host_call_registers(&self) -> &[Register; HOST_CALL_INPUT_REGISTERS_COUNT] {
        &self.state.registers
    }

    //
    // VM state read functions
    //

    /// Read a byte from memory
    fn read_memory_byte(&self, address: MemAddress) -> Result<u8, PVMError> {
        Ok(self.state.memory.read_byte(address)?)
    }

    /// Read a specified number of bytes from memory starting at the given address
    fn read_memory_bytes(&self, address: MemAddress, length: usize) -> Result<Octets, PVMError> {
        Ok(self.state.memory.read_bytes(address, length)?)
    }

    //
    // VM state mutation function
    //

    fn apply_host_call_state_change(
        &mut self,
        change: HostCallVMStateChange,
    ) -> Result<(), PVMError> {
        // Apply register changes (register index 7 & 8)
        if let Some(r7) = change.r7_write {
            self.state.registers[7].value = r7;
        }
        if let Some(r8) = change.r8_write {
            self.state.registers[8].value = r8;
        }

        // Apply memory change
        let (start_address, data_len, data) = change.memory_write;
        if data_len as usize <= data.len() {
            for (offset, &byte) in data.iter().take(data_len as usize).enumerate() {
                if let Err(e) = self
                    .state
                    .memory
                    .write_byte(start_address.wrapping_add(offset as u32), byte)
                {
                    eprintln!(
                        "Warning: Failed to write to memory at address {:X}: {:?}",
                        start_address.wrapping_add(offset as u32),
                        e
                    );
                }
            }
        } else {
            eprintln!("Warning: Data length mismatch in memory changes");
        }

        // Apply gas change
        self.state.gas_counter -= change.gas_usage;

        // TODO: add a separate gas check logic outside this function
        // if self.state.gas_counter >= change.gas_usage {
        //     self.state.gas_counter -= change.gas_usage;
        // } else {
        //     return ExitReason::OutOfGas;
        // }

        Ok(())
    }

    //
    // Gas operations
    //

    fn charge_gas(&mut self, amount: UnsignedGas) -> Result<(), PVMError> {
        if self.state.gas_counter < amount {
            Err(PVMError::VMCoreError(OutOfGas))
        } else {
            self.state.gas_counter -= amount;
            Ok(())
        }
    }

    //
    // Common PVM invocation functions
    //

    /// Invoke the PVM with program and arguments
    /// This works as a common interface for the four PVM invocation entry-points
    ///
    /// Represents `Psi_M` of the GP
    pub fn common_invocation(
        state_manager: &StateManager,
        target_address: Address,
        standard_program: &[u8],
        pc: MemAddress,
        gas: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext,
    ) -> Result<CommonInvocationResult, PVMError> {
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let mut pvm = Self::new_from_standard_program(standard_program, args)?;
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas;

        let extended_invocation_result =
            pvm.extended_invocation(state_manager, target_address, context)?;

        match extended_invocation_result.exit_reason {
            ExitReason::OutOfGas => Ok(CommonInvocationResult::OutOfGas(ExitReason::OutOfGas)),
            ExitReason::RegularHalt => {
                let result = pvm.read_memory_bytes(
                    PVMCore::read_reg(&pvm.state, 10)?,
                    PVMCore::read_reg(&pvm.state, 11)? as usize,
                );

                Ok(match result {
                    Ok(bytes) => CommonInvocationResult::Result((pvm.state.gas_counter, bytes)),
                    Err(_) => {
                        CommonInvocationResult::ResultUnavailable((pvm.state.gas_counter, vec![]))
                    }
                })
            }
            _ => Ok(CommonInvocationResult::Failure(ExitReason::Panic)),
        }
    }

    /// Invoke the PVM general functions including host calls with arguments injected by the `Psi_M`
    /// common invocation function
    ///
    /// # Arguments
    ///
    /// * `&mut self` - Mutable reference to the PVM including program code and VM states
    /// * `context` - The invocation context
    ///
    /// Represents `Psi_H` of the GP
    fn extended_invocation(
        &mut self,
        state_manager: &StateManager,
        target_address: Address,
        context: &mut InvocationContext,
    ) -> Result<ExtendedInvocationResult, PVMError> {
        loop {
            let mut exit_reason = PVMCore::general_invocation(&mut self.state, &mut self.program)?;

            let host_call_result = match exit_reason {
                ExitReason::HostCall(h) => {
                    self.execute_host_function(state_manager, target_address, context, &h)?
                }
                _ => return Ok(ExtendedInvocationResult { exit_reason }),
            };

            let vm_state_change = match host_call_result {
                HostCallResult::PageFault(m) => {
                    exit_reason = ExitReason::PageFault(m);
                    return Ok(ExtendedInvocationResult {
                        exit_reason: ExitReason::PageFault(m),
                    });
                }
                HostCallResult::Accumulation(result) => result.vm_state_change,
                _ => unimplemented!("not yet implemented"), // TODO: add other cases
            };

            self.apply_host_call_state_change(vm_state_change)?; // update the vm states
            self.state.pc = PVMCore::next_pc(&self.state, &self.program); // increment the pc on host call success
        }
    }

    fn execute_host_function(
        &mut self,
        state_manager: &StateManager,
        target_address: Address,
        context: &mut InvocationContext,
        h: &HostCallType,
    ) -> Result<HostCallResult, PVMError> {
        let result = match h {
            //
            // General Functions
            //
            // TODO: better gas handling
            HostCallType::GAS => HostFunction::host_gas(self.state.gas_counter)?,
            HostCallType::LOOKUP => HostFunction::host_lookup(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::READ => HostFunction::host_read(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::WRITE => HostFunction::host_write(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::INFO => HostFunction::host_info(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,

            //
            // Accumulate Functions
            //
            HostCallType::EMPOWER => {
                HostFunction::host_empower(self.get_host_call_registers(), state_manager)?
            }
            HostCallType::ASSIGN => HostFunction::host_assign(
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::DESIGNATE => HostFunction::host_designate(
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::CHECKPOINT => {
                HostFunction::host_checkpoint(self.state.gas_counter, context)?
            }
            HostCallType::NEW => HostFunction::host_new(
                target_address, // creator_address
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,
            HostCallType::UPGRADE => HostFunction::host_upgrade(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::TRANSFER => HostFunction::host_transfer(
                target_address,
                self.state.gas_counter,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,
            HostCallType::QUIT => HostFunction::host_quit(
                target_address,
                self.state.gas_counter,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,
            HostCallType::SOLICIT => HostFunction::host_solicit(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            HostCallType::FORGET => HostFunction::host_forget(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,

            //
            // Refine Functions
            //
            HostCallType::HISTORICAL_LOOKUP => HostFunction::host_historical_lookup(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
            )?,
            // TODO: impl
            // HostCallType::IMPORT => HostFunction::host_import(
            //     self.get_host_call_registers(),
            //     &self.state.memory,
            // )?,
            // HostCallType::EXPORT => HostFunction::host_export(
            //     self.get_host_call_registers(),
            //     &self.state.memory,
            // )?,
            HostCallType::MACHINE => HostFunction::host_machine(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::PEEK => HostFunction::host_peek(self.get_host_call_registers(), context)?,
            HostCallType::POKE => HostFunction::host_poke(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::INVOKE => HostFunction::host_invoke(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::EXPORT => {
                HostFunction::host_expunge(self.get_host_call_registers(), context)?
            }
            _ => return Err(PVMError::VMCoreError(InvalidHostCallType)),
        };

        Ok(result)
    }
}
