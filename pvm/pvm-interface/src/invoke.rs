use crate::{error::PVMError, pvm::PVM};
use fr_common::{workloads::WorkExecutionResult, ServiceId, SignedGas, TimeslotIndex, UnsignedGas};
use fr_pvm_core::{
    interpreter::Interpreter,
    state::state_change::{HostCallVMStateChange, VMStateMutator},
};
use fr_pvm_host::{
    context::InvocationContext,
    error::HostCallError::InvalidExitReason,
    host_functions::{
        accumulate::AccumulateHostFunction, general::GeneralHostFunction,
        refine::RefineHostFunction, HostCallResult,
    },
};
use fr_pvm_types::{common::RegValue, exit_reason::ExitReason, hostcall::HostCallType};
use fr_state::manager::StateManager;
use std::sync::Arc;
use tracing::instrument;

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
    #[allow(clippy::too_many_arguments)]
    pub async fn invoke_with_args(
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        standard_program: &[u8],
        pc: RegValue,
        gas_limit: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
    ) -> Result<PVMInvocationResult, PVMError> {
        tracing::info!("Ψ_M invoked.");
        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let Ok(mut pvm) = PVM::new_with_standard_program(standard_program, args) else {
            tracing::error!("Failed to initialize PVM instance");
            return Ok(PVMInvocationResult::panic(0));
        };
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas_limit as SignedGas;

        let result = Self::invoke_extended(
            &mut pvm,
            state_manager,
            service_id,
            context,
            curr_timeslot_index,
        )
        .await?;
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
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
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
                    Self::execute_host_function(
                        pvm,
                        state_manager.clone(),
                        service_id,
                        context,
                        curr_timeslot_index,
                        &h,
                    )
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

    #[instrument(level = "trace", name = "exe_hc", skip_all)]
    async fn execute_host_function(
        pvm: &PVM,
        state_manager: Arc<StateManager>,
        service_id: ServiceId,
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
        h: &HostCallType,
    ) -> Result<HostCallResult, PVMError> {
        tracing::trace!("{:?}", h);
        let result = match h {
            // --- General Functions
            HostCallType::GAS => GeneralHostFunction::<StateManager>::host_gas(&pvm.state)?,
            HostCallType::FETCH => {
                GeneralHostFunction::<StateManager>::host_fetch(&pvm.state, context)?
            }
            HostCallType::LOOKUP => {
                GeneralHostFunction::<StateManager>::host_lookup(
                    service_id,
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::READ => {
                GeneralHostFunction::<StateManager>::host_read(
                    service_id,
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::WRITE => {
                GeneralHostFunction::<StateManager>::host_write(
                    service_id,
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::INFO => {
                GeneralHostFunction::<StateManager>::host_info(
                    service_id,
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }

            // ---Refine Functions
            HostCallType::HISTORICAL_LOOKUP => {
                RefineHostFunction::<StateManager>::host_historical_lookup(
                    service_id,
                    &pvm.state,
                    context,
                    state_manager,
                )
                .await?
            }
            HostCallType::EXPORT => {
                RefineHostFunction::<StateManager>::host_export(&pvm.state, context)?
            }
            HostCallType::MACHINE => {
                RefineHostFunction::<StateManager>::host_machine(&pvm.state, context)?
            }
            HostCallType::PEEK => {
                RefineHostFunction::<StateManager>::host_peek(&pvm.state, context)?
            }
            HostCallType::POKE => {
                RefineHostFunction::<StateManager>::host_poke(&pvm.state, context)?
            }
            HostCallType::PAGES => {
                RefineHostFunction::<StateManager>::host_pages(&pvm.state, context)?
            }
            HostCallType::INVOKE => {
                RefineHostFunction::<StateManager>::host_invoke(&pvm.state, context)?
            }
            HostCallType::EXPUNGE => {
                RefineHostFunction::<StateManager>::host_expunge(&pvm.state, context)?
            }

            // --- Accumulate Functions
            HostCallType::BLESS => {
                AccumulateHostFunction::<StateManager>::host_bless(&pvm.state, context)?
            }
            HostCallType::ASSIGN => {
                AccumulateHostFunction::<StateManager>::host_assign(&pvm.state, context)?
            }
            HostCallType::DESIGNATE => {
                AccumulateHostFunction::<StateManager>::host_designate(&pvm.state, context)?
            }
            HostCallType::CHECKPOINT => {
                AccumulateHostFunction::<StateManager>::host_checkpoint(&pvm.state, context)?
            }
            HostCallType::NEW => {
                AccumulateHostFunction::<StateManager>::host_new(
                    &pvm.state,
                    state_manager,
                    context,
                    curr_timeslot_index
                        .expect("Timeslot index should be provided for accumulate invocation"),
                )
                .await?
            }
            HostCallType::UPGRADE => {
                AccumulateHostFunction::<StateManager>::host_upgrade(
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::TRANSFER => {
                AccumulateHostFunction::<StateManager>::host_transfer(
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::EJECT => {
                AccumulateHostFunction::<StateManager>::host_eject(
                    &pvm.state,
                    state_manager,
                    context,
                    curr_timeslot_index
                        .expect("Timeslot index should be provided for accumulate invocation"),
                )
                .await?
            }
            HostCallType::QUERY => {
                AccumulateHostFunction::<StateManager>::host_query(
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::SOLICIT => {
                AccumulateHostFunction::<StateManager>::host_solicit(
                    &pvm.state,
                    state_manager,
                    context,
                    curr_timeslot_index
                        .expect("Timeslot index should be provided for accumulate invocation"),
                )
                .await?
            }
            HostCallType::FORGET => {
                AccumulateHostFunction::<StateManager>::host_forget(
                    &pvm.state,
                    state_manager,
                    context,
                    curr_timeslot_index
                        .expect("Timeslot index should be provided for accumulate invocation"),
                )
                .await?
            }
            HostCallType::YIELD => {
                AccumulateHostFunction::<StateManager>::host_yield(&pvm.state, context).await?
            }
            HostCallType::PROVIDE => {
                AccumulateHostFunction::<StateManager>::host_provide(
                    service_id,
                    &pvm.state,
                    state_manager,
                    context,
                )
                .await?
            }
            HostCallType::LOG => HostCallResult {
                exit_reason: ExitReason::Continue,
                vm_change: HostCallVMStateChange {
                    gas_charge: 0,
                    ..Default::default()
                },
            },
        };

        Ok(result)
    }
}
