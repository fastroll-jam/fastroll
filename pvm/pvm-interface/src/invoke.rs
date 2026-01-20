use crate::{error::PVMError, pvm::PVM};
use fr_common::{
    workloads::WorkExecutionResult, Hash32, ServiceId, SignedGas, TimeslotIndex, UnsignedGas,
    BLOCK_HISTORY_LENGTH, MAX_WORK_ITEMS_PER_PACKAGE,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_core::{
    error::VMCoreError,
    interpreter::Interpreter,
    program::{
        loader::ProgramLoader,
        types::{formatted_program::FormattedProgram, program_state::ProgramState},
    },
    state::state_change::VMStateMutator,
};
use fr_pvm_host::{
    context::InvocationContext,
    error::HostCallError::InvalidExitReason,
    host_functions::{
        accumulate::AccumulateHostFunction, debug::host_log, general::GeneralHostFunction,
        refine::RefineHostFunction, HostCallResult, HostCallReturnCode,
    },
};
use fr_pvm_types::{common::RegValue, exit_reason::ExitReason, hostcall::HostCallType};
use fr_state::manager::StateManager;
use mini_moka::sync::Cache;
use std::sync::{Arc, OnceLock};
use tracing::instrument;

struct CachedProgram {
    formatted_program: Arc<FormattedProgram>,
    program_state: Arc<ProgramState>,
}

/// Safe estimate of cache capacity to cover the typical set of frequently accessed programs.
const PROGRAM_CACHE_MAX_ENTRIES: u64 =
    (MAX_WORK_ITEMS_PER_PACKAGE * BLOCK_HISTORY_LENGTH * 8) as u64;

/// Global PVM program cache that is reused across multiple invocations.
static PROGRAM_CACHE: OnceLock<Cache<Hash32, Arc<CachedProgram>>> = OnceLock::new();

fn program_cache() -> &'static Cache<Hash32, Arc<CachedProgram>> {
    PROGRAM_CACHE.get_or_init(|| Cache::new(PROGRAM_CACHE_MAX_ENTRIES))
}

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

pub enum InvocationType {
    IsAuthorized,
    Accumulate,
    Refine,
}

impl InvocationType {
    pub fn is_valid_host_call_type(&self, h: &HostCallType) -> bool {
        match self {
            InvocationType::IsAuthorized => {
                matches!(
                    h,
                    HostCallType::GAS | HostCallType::FETCH | HostCallType::LOG
                )
            }
            InvocationType::Accumulate => {
                matches!(
                    h,
                    HostCallType::GAS
                        | HostCallType::FETCH
                        | HostCallType::READ
                        | HostCallType::WRITE
                        | HostCallType::LOOKUP
                        | HostCallType::INFO
                        | HostCallType::BLESS
                        | HostCallType::ASSIGN
                        | HostCallType::DESIGNATE
                        | HostCallType::CHECKPOINT
                        | HostCallType::NEW
                        | HostCallType::UPGRADE
                        | HostCallType::TRANSFER
                        | HostCallType::EJECT
                        | HostCallType::QUERY
                        | HostCallType::SOLICIT
                        | HostCallType::FORGET
                        | HostCallType::YIELD
                        | HostCallType::PROVIDE
                        | HostCallType::LOG
                )
            }
            InvocationType::Refine => {
                matches!(
                    h,
                    HostCallType::GAS
                        | HostCallType::FETCH
                        | HostCallType::HISTORICAL_LOOKUP
                        | HostCallType::EXPORT
                        | HostCallType::MACHINE
                        | HostCallType::PEEK
                        | HostCallType::POKE
                        | HostCallType::PAGES
                        | HostCallType::INVOKE
                        | HostCallType::EXPUNGE
                        | HostCallType::LOG
                )
            }
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
        invocation_type: &InvocationType,
        pc: RegValue,
        gas_limit: UnsignedGas,
        args: &[u8],
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
    ) -> Result<PVMInvocationResult, PVMError> {
        tracing::info!("Ψ_M invoked. s={service_id}");
        let program_hash = hash::<Blake2b256>(standard_program)?;
        // First attempt to fetch the program from the global program cache that is persisted across
        // multiple block executions. Decode and load program on cache miss only.
        let cached_program = if let Some(entry) = program_cache().get(&program_hash) {
            entry
        } else {
            let formatted_program = FormattedProgram::from_standard_program(standard_program)?;
            if !formatted_program.is_program_size_valid() {
                return Err(PVMError::VMCoreError(VMCoreError::InvalidProgram));
            }

            // Initialize the program state
            let mut program_state = ProgramState::default();
            ProgramLoader::load_program(&formatted_program.code, &mut program_state)?;

            let cached = Arc::new(CachedProgram {
                formatted_program: Arc::new(formatted_program),
                program_state: Arc::new(program_state),
            });
            program_cache().insert(program_hash, cached.clone());
            cached
        };

        // Initialize mutable PVM states: memory, registers, pc and gas_counter
        let Ok(mut pvm) = PVM::new_with_formatted_program(
            &cached_program.formatted_program,
            cached_program.program_state.clone(),
            args,
        ) else {
            tracing::error!("Failed to initialize PVM instance");
            return Ok(PVMInvocationResult::panic(0));
        };
        pvm.state.pc = pc;
        pvm.state.gas_counter = gas_limit as SignedGas;

        let result = Self::invoke_extended(
            &mut pvm,
            state_manager,
            service_id,
            invocation_type,
            context,
            curr_timeslot_index,
        )
        .await?;
        let gas_used = gas_limit - 0.max(pvm.state.gas_counter) as UnsignedGas;

        tracing::info!("Ψ_M Exit Reason: {:?}, s={service_id}", result.exit_reason);
        match result.exit_reason {
            ExitReason::OutOfGas => Ok(PVMInvocationResult::out_of_gas(gas_used)),
            ExitReason::RegularHalt => {
                let start_address = pvm.state.read_reg_as_mem_address(7)?;
                let data_len = pvm.state.read_reg(8) as usize;
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
        invocation_type: &InvocationType,
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
    ) -> Result<ExtendedInvocationResult, PVMError> {
        tracing::info!("Ψ_H invoked. s={service_id}");
        loop {
            let exit_reason = Interpreter::invoke_general(&mut pvm.state, &pvm.program_state)?;

            let host_call_result = match exit_reason {
                ExitReason::HostCall(h) => {
                    Self::execute_host_function(
                        pvm,
                        state_manager.clone(),
                        service_id,
                        invocation_type,
                        context,
                        curr_timeslot_index,
                        &h,
                    )
                    .await?
                }
                _ => return Ok(ExtendedInvocationResult { exit_reason }),
            };

            match host_call_result.exit_reason {
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
                    pvm.state.pc = Interpreter::next_pc(pvm.state.pc, &pvm.program_state);
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
        invocation_type: &InvocationType,
        context: &mut InvocationContext<StateManager>,
        curr_timeslot_index: Option<TimeslotIndex>,
        h: &HostCallType,
    ) -> Result<HostCallResult, PVMError> {
        // Mark HostCallType with `INVALID` variant if it is not allowed for the given invocation type
        let h_validated = if !invocation_type.is_valid_host_call_type(h) {
            &HostCallType::INVALID
        } else {
            h
        };

        let result = match h_validated {
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
                    curr_timeslot_index.ok_or(PVMError::MissingAccumulateTimeslot)?,
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
                    curr_timeslot_index.ok_or(PVMError::MissingAccumulateTimeslot)?,
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
                    curr_timeslot_index.ok_or(PVMError::MissingAccumulateTimeslot)?,
                )
                .await?
            }
            HostCallType::FORGET => {
                AccumulateHostFunction::<StateManager>::host_forget(
                    &pvm.state,
                    state_manager,
                    context,
                    curr_timeslot_index.ok_or(PVMError::MissingAccumulateTimeslot)?,
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
            HostCallType::LOG => host_log(&pvm.state)?,
            HostCallType::INVALID => {
                HostCallResult::continue_with_return_code(HostCallReturnCode::WHAT)
            }
        };

        Ok(result)
    }
}
