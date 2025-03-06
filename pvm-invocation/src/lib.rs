pub mod accumulation;

use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::*;
use rjam_crypto::octets_to_hash32;
use rjam_pvm::{CommonInvocationResult, PVM};
use rjam_pvm_core::types::{
    accumulation::AccumulateOperand,
    common::{ExportDataSegment, RegValue},
    error::{HostCallError::InvalidContext, PVMError},
    invoke_args::{AccumulateInvokeArgs, OnTransferInvokeArgs, RefineInvokeArgs},
};
use rjam_pvm_hostcall::context::{
    partial_state::{AccountSandbox, AccumulatePartialState},
    types::*,
};
use rjam_state::StateManager;
use rjam_types::common::{
    transfers::DeferredTransfer,
    workloads::{RefinementContext, WorkExecutionOutput, WorkPackage},
};
use std::sync::Arc;

// Initial Program Counters
const IS_AUTHORIZED_INITIAL_PC: RegValue = 0;
const REFINE_INITIAL_PC: RegValue = 0;
const ACCUMULATE_INITIAL_PC: RegValue = 5;
const ON_TRANSFER_INITIAL_PC: RegValue = 10;

#[derive(JamEncode)]
pub struct IsAuthorizedArgs {
    /// **`p`**: Work package
    package: WorkPackage,
    /// `c`: Core index to process the work package
    core_index: CoreIndex,
}

/// `Ψ_M` invocation function arguments for `Ψ_R`
#[derive(JamEncode)]
pub struct RefineVMArgs {
    /// Associated service id (`s` of `WorkItem`)
    service_id: ServiceId,
    /// Work item payload blob (**`y`** of `WorkItem`)
    work_payload: Vec<u8>,
    /// Work package hash (Hash of `WorkPackage`)
    work_package_hash: Hash32,
    /// Refinement context (**`x`** of `WorkPackage`)
    refinement_context: RefinementContext,
    /// Authorizer code hash (`u` of `WorkPackage`)
    auth_code_hash: Hash32,
}

pub struct RefineResult {
    pub output: WorkExecutionOutput,
    pub export_segments: Vec<ExportDataSegment>,
}

impl RefineResult {
    pub fn ok(output: Vec<u8>, export_segments: Vec<ExportDataSegment>) -> Self {
        Self {
            output: WorkExecutionOutput::Output(Octets::from_vec(output)),
            export_segments,
        }
    }

    pub fn ok_empty(export_segments: Vec<ExportDataSegment>) -> Self {
        Self {
            output: WorkExecutionOutput::ok_empty(),
            export_segments,
        }
    }

    pub fn bad() -> Self {
        Self {
            output: WorkExecutionOutput::bad(),
            export_segments: vec![],
        }
    }

    pub fn big() -> Self {
        Self {
            output: WorkExecutionOutput::big(),
            export_segments: vec![],
        }
    }

    pub fn out_of_gas() -> Self {
        Self {
            output: WorkExecutionOutput::out_of_gas(),
            export_segments: vec![],
        }
    }

    pub fn panic() -> Self {
        Self {
            output: WorkExecutionOutput::panic(),
            export_segments: vec![],
        }
    }
}

/// `Ψ_M` invocation function arguments for `Ψ_A`
#[derive(JamEncode)]
pub struct AccumulateVMArgs {
    /// Current timeslot index
    timeslot_index: u32,
    /// `s` of `AccumulateInvokeArgs`
    accumulate_host: ServiceId,
    /// **`o`** of `AccumulateInvokeArgs`
    operands: Vec<AccumulateOperand>,
}

#[derive(Default)]
pub struct AccumulateResult {
    /// **`o`**: The posterior partial state
    pub partial_state: AccumulatePartialState,
    /// **`t`**: All transfers deferred by a single-service accumulation
    pub deferred_transfers: Vec<DeferredTransfer>,
    /// `b`: Accumulation result hash
    pub yielded_accumulate_hash: Option<Hash32>,
    /// `u`: Amount of gas used by a single-service accumulation
    pub gas_used: UnsignedGas,
    pub accumulate_host: ServiceId,
}

pub struct BalanceChangeSet {
    pub recipient: ServiceId,
    pub added_amount: Balance,
}

/// `Ψ_M` invocation function arguments for `Ψ_T`
#[derive(JamEncode)]
pub struct OnTransferVMArgs {
    /// Current timeslot index
    timeslot_index: u32,
    /// `s` of `OnTransferInvokeArgs`
    destination: ServiceId,
    /// **`t`** of `OnTransferInvokeArgs`
    transfers: Vec<DeferredTransfer>,
}

#[derive(Default)]
pub struct OnTransferResult {
    pub balance_change_set: Option<BalanceChangeSet>,
    pub recipient_sandbox: Option<AccountSandbox>,
}

impl OnTransferResult {
    pub fn new(
        recipient: ServiceId,
        added_amount: Balance,
        recipient_sandbox: Option<AccountSandbox>,
    ) -> Self {
        let balance_change_set = if added_amount > 0 {
            Some(BalanceChangeSet {
                recipient,
                added_amount,
            })
        } else {
            None
        };

        Self {
            balance_change_set,
            recipient_sandbox,
        }
    }
}

pub struct PVMInvocation;

impl PVMInvocation {
    //
    // PVM invocation entry-points
    //

    /// IsAuthorized invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - State manager to access to the global state. This is only used for the code data lookup.
    /// * `args` - IsAuthorized arguments
    ///
    /// Represents `Ψ_I` of the GP
    pub async fn is_authorized(
        state_manager: Arc<StateManager>,
        args: &IsAuthorizedArgs,
    ) -> Result<WorkExecutionOutput, PVMError> {
        // retrieve the service account code via historical lookup
        let code = match state_manager
            .get_account_code_by_lookup(
                args.package.authorizer_service_id,
                args.package.context.lookup_anchor_timeslot,
                &args.package.authorizer.auth_code_hash,
            )
            .await?
        {
            Some(code) => code,
            None => {
                // failed to get the `is_authorized` code from the service account
                return Ok(WorkExecutionOutput::bad());
            }
        };

        let result = PVM::invoke_with_args(
            state_manager,
            args.package.authorizer_service_id,
            &code,
            IS_AUTHORIZED_INITIAL_PC,
            IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
            &args.encode()?,
            &mut InvocationContext::X_I, // not used
        )
        .await?;

        match result {
            CommonInvocationResult::OutOfGas(_) => Ok(WorkExecutionOutput::out_of_gas()),
            CommonInvocationResult::Panic(_) => Ok(WorkExecutionOutput::panic()),
            CommonInvocationResult::Result(output) => Ok(WorkExecutionOutput::ok(output)),
            CommonInvocationResult::ResultUnavailable => Ok(WorkExecutionOutput::ok_empty()),
        }
    }

    /// Refine invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - State manager to access to the global state. The only allowed access is the historical lookup.
    /// * `args` - Refine entry-point function arguments
    ///
    /// Represents `Ψ_R` of the GP
    pub async fn refine(
        state_manager: Arc<StateManager>,
        args: &RefineInvokeArgs,
    ) -> Result<RefineResult, PVMError> {
        let Some(work_item) = args.package.work_items.get(args.item_idx) else {
            return Ok(RefineResult::bad());
        };

        // Check the service account to run refinement exists in the global state
        let service_exists = state_manager.account_exists(work_item.service_id).await?;
        if !service_exists {
            return Ok(RefineResult::bad());
        }

        // Retrieve the service account code via the historical lookup function
        let code = match state_manager
            .get_account_code_by_lookup(
                work_item.service_id,
                args.package.context.lookup_anchor_timeslot,
                &work_item.service_code_hash,
            )
            .await?
        {
            Some(code) => code,
            None => {
                // failed to get the `refine` code from the service account
                return Ok(RefineResult::bad());
            }
        };

        if code.len() > MAX_SERVICE_CODE_SIZE {
            return Ok(RefineResult::big());
        }

        let vm_args = RefineVMArgs {
            service_id: work_item.service_id,
            work_payload: work_item.payload_blob.clone().into_vec(),
            work_package_hash: args.package.hash()?,
            refinement_context: args.package.context.clone(),
            auth_code_hash: args.package.authorizer.auth_code_hash,
        };

        let mut refine_ctx =
            InvocationContext::X_R(RefineHostContext::new_with_invoke_args(args.clone()));
        let result = PVM::invoke_with_args(
            state_manager,
            work_item.service_id,
            &code,
            REFINE_INITIAL_PC,
            work_item.refine_gas_limit,
            &vm_args.encode()?,
            &mut refine_ctx,
        )
        .await?;

        let RefineHostContext {
            export_segments, ..
        } = if let InvocationContext::X_R(x) = refine_ctx {
            x
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match result {
            CommonInvocationResult::Result(output) => Ok(RefineResult::ok(output, export_segments)),
            CommonInvocationResult::ResultUnavailable => {
                Ok(RefineResult::ok_empty(export_segments))
            }
            CommonInvocationResult::OutOfGas(_) => Ok(RefineResult::out_of_gas()),
            CommonInvocationResult::Panic(_) => Ok(RefineResult::panic()),
        }
    }

    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - State manager to access to the global state
    /// * `args` - Accumulate entry-point function arguments
    ///
    /// Represents `Ψ_A` of the GP
    pub async fn accumulate(
        state_manager: Arc<StateManager>,
        partial_state: &AccumulatePartialState,
        args: &AccumulateInvokeArgs,
    ) -> Result<AccumulateResult, PVMError> {
        let Some(code) = state_manager.get_account_code(args.accumulate_host).await? else {
            return Ok(AccumulateResult::default());
        };

        let curr_entropy = state_manager.get_entropy_accumulator().await?.current();
        let curr_timeslot = state_manager.get_timeslot().await?;

        let vm_args = AccumulateVMArgs {
            timeslot_index: curr_timeslot.slot(),
            accumulate_host: args.accumulate_host,
            operands: args.operands.clone(),
        };

        let ctx = AccumulateHostContext::new(
            state_manager.clone(),
            partial_state.clone(),
            args.accumulate_host,
            curr_entropy,
            &curr_timeslot,
        )
        .await?;
        let ctx_pair = AccumulateHostContextPair {
            x: Box::new(ctx.clone()),
            y: Box::new(ctx),
        };
        let mut accumulate_ctx = InvocationContext::X_A(ctx_pair);

        let result = PVM::invoke_with_args(
            state_manager,
            args.accumulate_host,
            &code,
            ACCUMULATE_INITIAL_PC,
            args.gas_limit,
            &vm_args.encode()?,
            &mut accumulate_ctx,
        )
        .await?;

        let AccumulateHostContextPair { x, y } =
            if let InvocationContext::X_A(pair) = accumulate_ctx {
                pair
            } else {
                return Err(PVMError::HostCallError(InvalidContext));
            };

        match result {
            CommonInvocationResult::Result(output) => {
                let accumulate_result_hash = if output.len() == HASH_SIZE {
                    octets_to_hash32(&output)
                } else {
                    x.yielded_accumulate_hash
                };

                Ok(AccumulateResult {
                    partial_state: x.partial_state,
                    deferred_transfers: x.deferred_transfers,
                    yielded_accumulate_hash: accumulate_result_hash,
                    gas_used: x.gas_used,
                    accumulate_host: x.accumulate_host,
                })
            }
            CommonInvocationResult::ResultUnavailable => Ok(AccumulateResult {
                partial_state: x.partial_state,
                deferred_transfers: x.deferred_transfers,
                yielded_accumulate_hash: x.yielded_accumulate_hash,
                gas_used: x.gas_used,
                accumulate_host: x.accumulate_host,
            }),
            CommonInvocationResult::OutOfGas(_) | CommonInvocationResult::Panic(_) => {
                Ok(AccumulateResult {
                    partial_state: y.partial_state,
                    deferred_transfers: y.deferred_transfers,
                    yielded_accumulate_hash: y.yielded_accumulate_hash,
                    gas_used: x.gas_used, // Note: taking gas usage from the `x` context
                    accumulate_host: x.accumulate_host,
                })
            }
        }
    }

    /// OnTransfer invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - State manager to access to the global state
    /// * `args` - On-Transfer entry-point function arguments
    ///
    /// Represents `Ψ_T` of the GP
    pub async fn on_transfer(
        state_manager: Arc<StateManager>,
        args: &OnTransferInvokeArgs,
    ) -> Result<OnTransferResult, PVMError> {
        if args.transfers.is_empty() {
            return Ok(OnTransferResult::default());
        }

        let total_amount = args.transfers.iter().map(|t| t.amount).sum();
        let total_gas_limit = args.transfers.iter().map(|t| t.gas_limit).sum();

        let Some(code) = state_manager.get_account_code(args.destination).await? else {
            return Ok(OnTransferResult::default());
        };

        let curr_timeslot = state_manager.get_timeslot().await?;

        let vm_args = OnTransferVMArgs {
            timeslot_index: curr_timeslot.slot(),
            destination: args.destination,
            transfers: args.transfers.clone(),
        };

        let ctx = OnTransferHostContext::new(state_manager.clone(), args.destination).await?;
        let mut on_transfer_ctx = InvocationContext::X_T(ctx);

        let _ = PVM::invoke_with_args(
            state_manager.clone(),
            args.destination,
            &code,
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &vm_args.encode()?,
            &mut on_transfer_ctx,
        )
        .await?;

        let OnTransferHostContext {
            mut accounts_sandbox,
        } = if let InvocationContext::X_T(x) = on_transfer_ctx {
            x
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        let recipient_sandbox = accounts_sandbox
            .get_account_sandbox(state_manager, args.destination)
            .await?
            .cloned();

        Ok(OnTransferResult::new(
            args.destination,
            total_amount,
            recipient_sandbox,
        ))
    }
}
