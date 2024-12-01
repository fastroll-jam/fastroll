use rjam_common::*;
use rjam_pvm_core::{
    constants::*,
    core::{PVMCore, VMState},
    program::program_decoder::{FormattedProgram, ProgramDecoder, ProgramState},
    state::{
        memory::{AccessType, MemAddress, Memory},
        register::Register,
    },
    types::{
        common::{ExitReason, RegValue},
        error::{HostCallError::InvalidMemoryWrite, PVMError, VMCoreError::*},
        hostcall::HostCallType,
    },
    utils::VMUtils,
};
use rjam_pvm_hostcall::{
    contexts::InvocationContext,
    host_functions::{HostCallChangeSet, HostCallVMStateChange, HostFunction},
};
use rjam_state::StateManager;

#[allow(dead_code)]
enum ExecutionResult {
    Complete(ExitReason),
    HostCall(HostCallType),
}

// TODO: check the GP - `InvocationContext` elided for `Result` and `ResultUnavailable`
pub enum CommonInvocationResult {
    OutOfGas(ExitReason),
    Result((UnsignedGas, Vec<u8>)), // (posterior_gas, return_value)
    ResultUnavailable((UnsignedGas, Vec<u8>)), // (posterior_gas, [])
    Failure(ExitReason),            // panic
}

// TODO: add other posterior VM states?
struct ExtendedInvocationResult {
    exit_reason: ExitReason,
}

/// Main stateful PVM struct
#[derive(Default)]
pub struct PVM {
    state: VMState,
    program_blob: Vec<u8>,       // serialization of `PVM.program`
    program_state: ProgramState, // initialized in the general invocation `Ψ`
}

impl PVM {
    //
    // VM states initialization
    //

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` of the GP
    fn init_with_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, PVMError> {
        let mut pvm = Self::default();

        // decode program and check validity
        let formatted_program = ProgramDecoder::decode_standard_program(standard_program)?;
        if !formatted_program.validate_program_size() {
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
        let o_start = REGION_SIZE as MemAddress; // Z_Q
        let o_padding_end = o_start + VMUtils::page_align(fp.static_size as usize) as MemAddress;
        memory.init_range_access(o_start..o_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(o_start, &fp.static_data)?;

        // Read-write heap data (w)
        let w_start =
            (2 * REGION_SIZE + VMUtils::region_align(fp.static_size as usize)) as MemAddress;
        let w_padding_end = w_start
            + VMUtils::page_align(fp.heap_size as usize) as MemAddress
            + fp.extra_heap_pages as MemAddress * PAGE_SIZE as MemAddress;
        memory.init_range_access(w_start..w_padding_end, AccessType::ReadWrite)?;
        memory.write_bytes(w_start, &fp.heap_data)?;
        memory.heap_start = w_start;

        // Stack (s)
        let s_start =
            ((1 << 32) - 2 * REGION_SIZE - INIT_SIZE - VMUtils::page_align(fp.stack_size as usize))
                as MemAddress;
        let s_end = ((1 << 32) - 2 * REGION_SIZE - INIT_SIZE) as MemAddress;
        memory.init_range_access(s_start..s_end, AccessType::ReadWrite)?;

        // Arguments (a)
        let a_start = ((1 << 32) - REGION_SIZE - INIT_SIZE) as MemAddress;
        let a_padding_end = a_start + VMUtils::page_align(args.len()) as MemAddress;
        memory.init_range_access(a_start..a_padding_end, AccessType::ReadOnly)?;
        memory.write_bytes(a_start, args)?;

        // Other addresses are inaccessible
        memory.init_range_access(0..o_start, AccessType::Inaccessible)?;
        memory.init_range_access(o_padding_end..w_start, AccessType::Inaccessible)?;
        memory.init_range_access(w_padding_end..s_start, AccessType::Inaccessible)?;
        memory.init_range_access(s_end..a_start, AccessType::Inaccessible)?;
        memory.init_range_access(a_padding_end..MemAddress::MAX, AccessType::Inaccessible)?;

        self.state.memory = memory;
        Ok(())
    }

    fn initialize_registers(&mut self, args_len: usize) {
        self.state.registers[0].value = (1 << 32) - (1 << 16);
        self.state.registers[1].value = (1 << 32) - (2 * REGION_SIZE + INIT_SIZE) as RegValue;
        self.state.registers[7].value = (1 << 32) - (REGION_SIZE + INIT_SIZE) as RegValue;
        self.state.registers[8].value = args_len as RegValue;
    }

    //
    // PVM helper function
    //

    /// Get a reference to registers for host call function arguments
    pub fn get_host_call_registers(&self) -> &[Register; REGISTERS_COUNT] {
        &self.state.registers
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
        change: HostCallVMStateChange,
    ) -> Result<SignedGas, PVMError> {
        // Apply register changes (register index 7 & 8)
        if let Some(r7) = change.r7_write {
            self.state.registers[7].value = r7;
        }
        if let Some(r8) = change.r8_write {
            self.state.registers[8].value = r8;
        }

        // Apply memory change
        let (start_address, data_len, data) = change.memory_write;
        if data_len as usize > data.len() {
            return Err(PVMError::HostCallError(InvalidMemoryWrite));
        }
        for (offset, &byte) in data.iter().take(data_len as usize).enumerate() {
            self.state
                .memory
                .write_byte(start_address.wrapping_add(offset as u32), byte)?;
        }

        // Apply gas change
        self.state.gas_counter -= change.gas_charge;

        // Check gas counter and apply gas change
        let post_gas = PVMCore::apply_gas_cost(&mut self.state, change.gas_charge)?;
        Ok(post_gas)
    }

    //
    // Gas operations
    //

    #[allow(dead_code)]
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

    /// Invokes the PVM with standard program blob and arguments.
    /// This works as a common interface for the four PVM invocation entry-points.
    ///
    /// # Input Program
    /// This function accepts a standard program blob as input, which is then decoded into a
    /// `FormattedProgram` type. The decoding process extracts information about the memory layout
    /// necessary for initialization. Subsequently, the code section of the `FormattedProgram`
    /// is loaded as an immutable state within the `PVM`. This immutable state allows the program code
    /// to be utilized during the execution of the `extended_invocation` and `general_invocation` functions.
    ///
    /// Represents `Ψ_M` of the GP.
    pub fn common_invocation(
        state_manager: &StateManager,
        target_address: Address,
        standard_program: &[u8],
        pc: RegValue,
        gas: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext,
    ) -> Result<CommonInvocationResult, PVMError> {
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let mut pvm = Self::init_with_standard_program(standard_program, args)?;
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas;

        let extended_invocation_result =
            pvm.extended_invocation(state_manager, target_address, context)?;

        match extended_invocation_result.exit_reason {
            ExitReason::OutOfGas => Ok(CommonInvocationResult::OutOfGas(ExitReason::OutOfGas)),
            ExitReason::RegularHalt => {
                let result = pvm.read_memory_bytes(
                    PVMCore::read_reg_as_mem_address(&pvm.state, 10)?,
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
    /// # Input Program
    /// This function utilizes the program component of the `PVM` state.
    ///
    /// Represents `Ψ_H` of the GP.
    fn extended_invocation(
        &mut self,
        state_manager: &StateManager,
        target_address: Address,
        context: &mut InvocationContext,
    ) -> Result<ExtendedInvocationResult, PVMError> {
        loop {
            let exit_reason = PVMCore::general_invocation(
                &mut self.state,
                &mut self.program_state,
                &self.program_blob,
            )?;

            let host_call_change_set = match exit_reason {
                ExitReason::HostCall(h) => {
                    self.execute_host_function(state_manager, target_address, context, &h)?
                    // TODO: we need to pass "context time" here
                }
                _ => return Ok(ExtendedInvocationResult { exit_reason }),
            };

            let post_gas = self.apply_host_call_state_change(host_call_change_set.vm_change)?; // update the vm states
            if post_gas < 0 {
                return Ok(ExtendedInvocationResult {
                    exit_reason: ExitReason::OutOfGas,
                });
            }
            self.state.pc = PVMCore::next_pc(&self.state, &self.program_state); // increment the pc on host call success
        }
    }

    fn execute_host_function(
        &mut self,
        state_manager: &StateManager,
        target_address: Address,
        context: &mut InvocationContext,
        h: &HostCallType,
    ) -> Result<HostCallChangeSet, PVMError> {
        let result = match h {
            //
            // General Functions
            //
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
            HostCallType::BLESS => HostFunction::host_bless(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::ASSIGN => HostFunction::host_assign(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::DESIGNATE => HostFunction::host_designate(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::CHECKPOINT => {
                HostFunction::host_checkpoint(self.state.gas_counter, context)?
            }
            HostCallType::NEW => HostFunction::host_new(
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,
            HostCallType::UPGRADE => HostFunction::host_upgrade(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::TRANSFER => HostFunction::host_transfer(
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
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,
            HostCallType::FORGET => HostFunction::host_forget(
                self.get_host_call_registers(),
                &self.state.memory,
                state_manager,
                context,
            )?,

            //
            // Refine Functions
            //
            HostCallType::HISTORICAL_LOOKUP => HostFunction::host_historical_lookup(
                target_address,
                self.get_host_call_registers(),
                &self.state.memory,
                context,
                state_manager,
            )?,
            HostCallType::IMPORT => HostFunction::host_import(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
            HostCallType::EXPORT => HostFunction::host_export(
                self.get_host_call_registers(),
                &self.state.memory,
                context,
            )?,
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
            HostCallType::EXPUNGE => {
                HostFunction::host_expunge(self.get_host_call_registers(), context)?
            }
            // TODO: host call type validation and handling `WHAT` host call result
            _ => return Err(PVMError::VMCoreError(InvalidHostCallType)),
        };

        Ok(result)
    }
}
