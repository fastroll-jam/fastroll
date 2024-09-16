use bit_vec::BitVec;
use jam_codec::{JamEncode, JamInput};
use jam_common::{AccountAddress, Octets, UnsignedGas};
use jam_crypto::utils::octets_to_hash32;
use jam_host_interface::{
    contexts::{AccumulationContext, InvocationContext},
    host_functions::{AccumulationResult, HostCallResult, HostCallVMStateChange, HostFunction},
};
use jam_pvm_core::{
    accumulation::AccumulationOperand,
    constants::{
        HOST_CALL_INPUT_REGISTERS_COUNT, INPUT_SIZE, MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT,
        SEGMENT_SIZE,
    },
    hostcall::HostCallType,
    memory::{AccessType, MemAddress, Memory},
    program_decoder::{FormattedProgram, ProgramDecoder},
    register::Register,
    types::{ExitReason, VMError},
    vm_core::{PVMCore, Program, VMState},
    vm_utils::VMUtils,
};
use jam_types::state::services::ServiceAccounts;
//
// Enums
//

enum ExecutionResult {
    Complete(ExitReason),
    HostCall(HostCallType),
}

enum CommonInvocationResult {
    OutOfGas(ExitReason, InvocationContext), // (exit_reason, context)
    Result(UnsignedGas, Octets),             // (posterior_gas, return_value);
    ResultUnavailable(UnsignedGas),          // (posterior_gas, [])
    Failure(ExitReason, InvocationContext),  // (panic, context)
}

//
// Structs
//

/// Main stateful PVM struct
struct PVM {
    state: VMState,
    program: Program,
}

struct ExtendedInvocationResult {
    exit_reason: ExitReason,
    post_context: InvocationContext,
    // TODO: add other posterior VM states?
}

impl Default for PVM {
    fn default() -> Self {
        Self {
            state: VMState {
                registers: [Register { value: 0 }; REGISTERS_COUNT],
                memory: Memory::new(0, 0),
                pc: 0,
                gas_counter: 0,
            },
            program: Program {
                program_code: vec![],
                instructions: vec![],
                jump_table: vec![],
                opcode_bitmask: BitVec::new(),
                basic_block_bitmask: BitVec::new(),
            },
        }
    }
}

impl PVM {
    //
    // VM states initialization
    //

    /// Initialize memory and registers of PVM with provided program and arguments
    ///
    /// Represents `Y` of the GP
    fn new_from_standard_program(standard_program: &[u8], args: &[u8]) -> Result<Self, VMError> {
        let mut pvm = PVM::default();

        // decode program and check validity
        let formatted_program = ProgramDecoder::decode_standard_program(standard_program)?;
        if !formatted_program.check_size_limit() {
            return Err(VMError::InvalidProgram);
        }

        pvm.setup_memory_layout(&formatted_program, &args)?;
        pvm.initialize_registers(args.len());
        pvm.program.program_code = formatted_program.code;

        Ok(pvm)
    }

    fn setup_memory_layout(&mut self, fp: &FormattedProgram, args: &[u8]) -> Result<(), VMError> {
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
        self.state.registers[1].value = u32::MAX - (1 << 16) + 1;
        self.state.registers[2].value = u32::MAX - (2 * SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[10].value = u32::MAX - (SEGMENT_SIZE + INPUT_SIZE) as u32 + 1;
        self.state.registers[11].value = args_len as u32;
    }

    //
    // PVM helper function
    //

    /// Get a reference to the first 6 registers for host call functions
    pub fn get_host_call_registers(&self) -> &[Register; HOST_CALL_INPUT_REGISTERS_COUNT] {
        self.state.registers[..HOST_CALL_INPUT_REGISTERS_COUNT]
            .try_into()
            .unwrap()
    }

    //
    // VM state read functions
    //

    /// Read a byte from memory
    fn read_memory_byte(&self, address: MemAddress) -> Result<u8, VMError> {
        Ok(self.state.memory.read_byte(address)?)
    }

    /// Read a specified number of bytes from memory starting at the given address
    fn read_memory_bytes(&self, address: MemAddress, length: usize) -> Result<Octets, VMError> {
        Ok(self.state.memory.read_bytes(address, length)?)
    }

    //
    // VM state mutation function
    //

    fn apply_host_call_state_change(
        &mut self,
        change: HostCallVMStateChange,
    ) -> Result<(), VMError> {
        // Apply register changes (register index 0 & 1)
        if let Some(r0) = change.r0_write {
            self.state.registers[0].value = r0;
        }
        if let Some(r1) = change.r1_write {
            self.state.registers[1].value = r1;
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

    fn charge_gas(&mut self, amount: UnsignedGas) -> Result<(), VMError> {
        if self.state.gas_counter < amount {
            Err(VMError::OutOfGas)
        } else {
            self.state.gas_counter -= amount;
            Ok(())
        }
    }

    //
    // PVM invocation functions
    //

    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `service_accounts` - The current global state of service accounts, after preimage integration but before accumulation
    /// * `service_account_address` - The address of the service account invoking the accumulation
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation operation
    /// * `operands` - A vector of `AccumulationOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Psi_A` of the GP
    pub(crate) fn accumulate(
        service_accounts: &ServiceAccounts,
        service_account_address: AccountAddress,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulationOperand>,
    ) -> Result<AccumulationResult, VMError> {
        // TODO: interface for fetching on-chain account from address
        let invoker_account = service_accounts
            .0
            .get(&service_account_address)
            .unwrap()
            .clone();

        let code = invoker_account.get_code();

        if operands.is_empty() || code.is_none() {
            return Ok(AccumulationResult::Unchanged(invoker_account));
        }

        // TODO: check using mutable references
        // `x` for a regular dimension and `y` for an exceptional dimension
        let (x, y) = AccumulationContext::initialize_context_pair(
            service_accounts,
            invoker_account.clone(),
            service_account_address,
        )?;

        let common_invocation_result = Self::common_invocation(
            &code.unwrap()[..],
            2,
            gas_limit,
            &operands.encode()?,
            InvocationContext::X_A((x.clone(), y.clone())),
        )?;

        return match common_invocation_result {
            CommonInvocationResult::Result(_gas, output) => {
                Ok(AccumulationResult::Result(x, octets_to_hash32(output)))
            }
            CommonInvocationResult::ResultUnavailable(_gas) => {
                Ok(AccumulationResult::Result(x, None))
            }
            CommonInvocationResult::OutOfGas(_, _) | CommonInvocationResult::Failure(_, _) => {
                Ok(AccumulationResult::Result(y, None))
            }
        };
    }

    /// Invoke the PVM with program and arguments
    /// This works as a common interface for the four PVM invocation entry-points
    ///
    /// Represents `Psi_M` of the GP
    pub(crate) fn common_invocation(
        standard_program: &[u8],
        pc: MemAddress,
        gas: UnsignedGas,
        args: &[u8],
        context: InvocationContext,
    ) -> Result<CommonInvocationResult, VMError> {
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let mut pvm = Self::new_from_standard_program(standard_program, args)?;
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas;

        let extended_invocation_result = pvm.extended_invocation(context.clone())?;

        match extended_invocation_result.exit_reason {
            ExitReason::OutOfGas => Ok(CommonInvocationResult::OutOfGas(
                ExitReason::OutOfGas,
                extended_invocation_result.post_context,
            )),
            ExitReason::RegularHalt => {
                let result = pvm.read_memory_bytes(
                    PVMCore::read_reg(&pvm.state, 10)?,
                    PVMCore::read_reg(&pvm.state, 11)? as usize,
                );

                Ok(match result {
                    Ok(bytes) => CommonInvocationResult::Result(pvm.state.gas_counter, bytes),
                    Err(_) => CommonInvocationResult::ResultUnavailable(pvm.state.gas_counter),
                })
            }
            _ => Ok(CommonInvocationResult::Failure(ExitReason::Panic, context)),
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
        context: InvocationContext,
    ) -> Result<ExtendedInvocationResult, VMError> {
        let mut context = context.clone();

        loop {
            // let mut exit_reason = self.general_invocation()?;
            let mut exit_reason = PVMCore::general_invocation(&mut self.state, &mut self.program)?;

            let host_call_result = match exit_reason {
                ExitReason::HostCall(h) => self.execute_host_function(&context, &h)?,
                _ => {
                    return Ok(ExtendedInvocationResult {
                        exit_reason,
                        post_context: context,
                    })
                }
            };

            let (vm_state_change, post_context) = match host_call_result {
                HostCallResult::PageFault(m) => {
                    exit_reason = ExitReason::PageFault(m);
                    return Ok(ExtendedInvocationResult {
                        exit_reason: ExitReason::PageFault(m),
                        post_context: context,
                    });
                }
                HostCallResult::Accumulation(result) => (
                    result.vm_state_change,
                    InvocationContext::X_A(result.post_contexts),
                ),
                _ => unimplemented!("not yet implemented"), // TODO: add other cases
            };

            self.apply_host_call_state_change(vm_state_change)?; // update the vm states
            context = post_context; // update the invocation context for the next call
            self.state.pc = PVMCore::next_pc(&self.state, &self.program); // increment the pc on host call success
        }
    }

    fn execute_host_function(
        &mut self,
        context: &InvocationContext,
        h: &HostCallType,
    ) -> Result<HostCallResult, VMError> {
        // TODO: add other host function cases
        let result = match h {
            // TODO: better gas handling
            HostCallType::GAS => HostFunction::host_gas(
                self.state.gas_counter,
                self.get_host_call_registers(),
                &context,
            )?,
            HostCallType::EMPOWER => HostFunction::host_empower(
                self.state.gas_counter,
                self.get_host_call_registers(),
                &self.state.memory,
                &context,
            )?,
            _ => return Err(VMError::InvalidHostCallType),
        };

        Ok(result)
    }
}
