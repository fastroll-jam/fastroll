use crate::{error::PVMError, pvm::PVM};
use fr_common::{workloads::WorkExecutionResult, ServiceId, SignedGas, UnsignedGas};
use fr_pvm_core::{interpreter::Interpreter, state::state_change::VMStateMutator};
use fr_pvm_host::{
    context::InvocationContext,
    error::HostCallError::InvalidExitReason,
    host_functions::{HostCallResult, HostFunction},
};
use fr_pvm_types::{common::RegValue, exit_reason::ExitReason, hostcall::HostCallType};
use fr_state::manager::StateManager;
use std::sync::Arc;

struct ExtendedInvocationResult {
    exit_reason: ExitReason,
}

pub struct PVMInvocationResult {
    pub gas_used: UnsignedGas,
    pub output: PVMInvocationOutput,
}

impl PVMInvocationResult {
    pub fn with_output(output: Vec<u8>, gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: PVMInvocationOutput::Output(output),
        }
    }

    pub fn no_output(gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: PVMInvocationOutput::OutputUnavailable,
        }
    }

    pub fn out_of_gas(gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: PVMInvocationOutput::OutOfGas(ExitReason::OutOfGas),
        }
    }

    pub fn panic(gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: PVMInvocationOutput::Panic(ExitReason::Panic),
        }
    }
}

pub enum PVMInvocationOutput {
    /// Regular halt with return value
    Output(Vec<u8>),
    /// Regular halt with no return value
    OutputUnavailable,
    /// Out of gas
    OutOfGas(ExitReason),
    /// Panic
    Panic(ExitReason),
}

impl From<PVMInvocationOutput> for WorkExecutionResult {
    fn from(output: PVMInvocationOutput) -> Self {
        match output {
            PVMInvocationOutput::OutOfGas(_) => Self::out_of_gas(),
            PVMInvocationOutput::Panic(_) => Self::panic(),
            PVMInvocationOutput::Output(output) => Self::ok(output),
            PVMInvocationOutput::OutputUnavailable => Self::ok_empty(),
        }
    }
}

pub struct PVMInterface;
impl PVMInterface {
    /// Initializes a PVM instance and executes it with a standard program blob and some arguments.
    /// This works as a common interface for the four PVM invocation entry-points.
    ///
    /// # Input Program
    /// This function accepts a standard program blob as input, which is then decoded into a
    /// `FormattedProgram` type. The decoding process extracts information about the memory layout
    /// necessary for initialization. Subsequently, the `code` section of the `FormattedProgram`
    /// is loaded as an immutable state within the `PVM`. This immutable state allows the program code
    /// to be utilized during the execution of the `invoke_extended` and `invoke_general` functions.
    ///
    /// Represents `Ψ_M` of the GP.
    pub async fn invoke_with_args(
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        standard_program: &[u8],
        pc: RegValue,
        gas_limit: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext,
    ) -> Result<PVMInvocationResult, PVMError> {
        tracing::info!("Ψ_M invoked.");
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let Ok(mut pvm) = PVM::new_with_standard_program(standard_program, args) else {
            tracing::error!("Failed to initialize PVM instance");
            return Ok(PVMInvocationResult::panic(0));
        };
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas_limit as SignedGas;

        let result = Self::invoke_extended(&mut pvm, state_manager, service_id, context).await?;
        let gas_used = gas_limit - 0.max(pvm.state.gas_counter) as UnsignedGas;

        tracing::info!("Ψ_M Exit Reason: {:?}", result.exit_reason);
        match result.exit_reason {
            ExitReason::OutOfGas => Ok(PVMInvocationResult::out_of_gas(gas_used)),
            ExitReason::RegularHalt => {
                let start_address = pvm.state.read_reg_as_mem_address(10)?;
                let data_len = pvm.state.read_reg(11) as usize;
                if !pvm
                    .state
                    .memory
                    .is_address_range_readable(start_address, data_len)
                {
                    return Ok(PVMInvocationResult::no_output(gas_used));
                }

                let bytes = pvm.read_memory_bytes(start_address, data_len)?;
                Ok(PVMInvocationResult::with_output(bytes, gas_used))
            }
            _ => Ok(PVMInvocationResult::panic(gas_used)),
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
        pvm: &mut PVM,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        context: &mut InvocationContext,
    ) -> Result<ExtendedInvocationResult, PVMError> {
        tracing::info!("Ψ_H invoked.");
        loop {
            let exit_reason = Interpreter::invoke_general(
                &mut pvm.state,
                &mut pvm.program_state,
                &pvm.program_blob,
            )?;

            let host_call_result = match exit_reason {
                ExitReason::HostCall(h) => {
                    tracing::debug!("Hostcall: {h:?}");
                    Self::execute_host_function(pvm, state_manager.clone(), service_id, context, &h)
                        .await?
                }
                _ => return Ok(ExtendedInvocationResult { exit_reason }),
            };

            match host_call_result.exit_reason {
                exit_reason @ ExitReason::PageFault(_) => {
                    // Host functions explicitly check memory accessibility prior to returning
                    // the VM change set. Therefore, unless the host-call exit reason is `PageFault`,
                    // `VMStateMutator::apply_host_call_state_change` can safely apply state changes
                    // without handling page fault scenarios.
                    return Ok(ExtendedInvocationResult { exit_reason });
                }
                ExitReason::Continue => {
                    // update the vm states
                    let post_gas = VMStateMutator::apply_host_call_state_change(
                        &mut pvm.state,
                        &host_call_result.vm_change,
                    )?;
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
                    VMStateMutator::apply_host_call_state_change(
                        &mut pvm.state,
                        &host_call_result.vm_change,
                    )?;
                    return Ok(ExtendedInvocationResult { exit_reason });
                }
                _ => return Err(PVMError::HostCallError(InvalidExitReason)),
            }
        }
    }

    async fn execute_host_function(
        pvm: &PVM,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        context: &mut InvocationContext,
        h: &HostCallType,
    ) -> Result<HostCallResult, PVMError> {
        tracing::trace!("{:?}", h);
        let result = match h {
            // --- General Functions
            HostCallType::GAS => HostFunction::host_gas(&pvm.state)?,
            HostCallType::FETCH => HostFunction::host_fetch(&pvm.state, context)?,
            HostCallType::LOOKUP => {
                HostFunction::host_lookup(service_id, &pvm.state, state_manager, context).await?
            }
            HostCallType::READ => {
                HostFunction::host_read(service_id, &pvm.state, state_manager, context).await?
            }
            HostCallType::WRITE => {
                HostFunction::host_write(service_id, &pvm.state, state_manager, context).await?
            }
            HostCallType::INFO => {
                HostFunction::host_info(service_id, &pvm.state, state_manager, context).await?
            }

            // ---Refine Functions
            HostCallType::HISTORICAL_LOOKUP => {
                HostFunction::host_historical_lookup(service_id, &pvm.state, context, state_manager)
                    .await?
            }
            HostCallType::EXPORT => HostFunction::host_export(&pvm.state, context)?,
            HostCallType::MACHINE => HostFunction::host_machine(&pvm.state, context)?,
            HostCallType::PEEK => HostFunction::host_peek(&pvm.state, context)?,
            HostCallType::POKE => HostFunction::host_poke(&pvm.state, context)?,
            HostCallType::PAGES => HostFunction::host_pages(&pvm.state, context)?,
            HostCallType::INVOKE => HostFunction::host_invoke(&pvm.state, context)?,
            HostCallType::EXPUNGE => HostFunction::host_expunge(&pvm.state, context)?,

            // --- Accumulate Functions
            HostCallType::BLESS => HostFunction::host_bless(&pvm.state, context)?,
            HostCallType::ASSIGN => HostFunction::host_assign(&pvm.state, context)?,
            HostCallType::DESIGNATE => HostFunction::host_designate(&pvm.state, context)?,
            HostCallType::CHECKPOINT => HostFunction::host_checkpoint(&pvm.state, context)?,
            HostCallType::NEW => HostFunction::host_new(&pvm.state, state_manager, context).await?,
            HostCallType::UPGRADE => {
                HostFunction::host_upgrade(&pvm.state, state_manager, context).await?
            }
            HostCallType::TRANSFER => {
                HostFunction::host_transfer(&pvm.state, state_manager, context).await?
            }
            HostCallType::EJECT => {
                HostFunction::host_eject(&pvm.state, state_manager, context).await?
            }
            HostCallType::QUERY => {
                HostFunction::host_query(&pvm.state, state_manager, context).await?
            }
            HostCallType::SOLICIT => {
                HostFunction::host_solicit(&pvm.state, state_manager, context).await?
            }
            HostCallType::FORGET => {
                HostFunction::host_forget(&pvm.state, state_manager, context).await?
            }
            HostCallType::YIELD => HostFunction::host_yield(&pvm.state, context).await?,
            HostCallType::PROVIDE => {
                HostFunction::host_provide(service_id, &pvm.state, state_manager, context).await?
            }
        };

        Ok(result)
    }
}
