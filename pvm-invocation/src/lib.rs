pub mod accumulation;

use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::*;
use rjam_crypto::octets_to_hash32;
use rjam_pvm::{CommonInvocationResult, PVM};
use rjam_pvm_core::types::{
    accumulation::AccumulateOperand,
    common::{ExportDataSegment, RegValue},
    error::{HostCallError::InvalidContext, PVMError},
    invoke_args::RefineInvokeArgs,
};
use rjam_pvm_hostcall::context::types::*;
use rjam_state::StateManager;
use rjam_types::{
    common::{
        transfers::DeferredTransfer,
        workloads::{RefinementContext, WorkExecutionOutput, WorkPackage},
    },
    state::timeslot::Timeslot,
};

// Initial Program Counters
const IS_AUTHORIZED_INITIAL_PC: RegValue = 0;
const REFINE_INITIAL_PC: RegValue = 0;
const ACCUMULATE_INITIAL_PC: RegValue = 5;
const ON_TRANSFER_INITIAL_PC: RegValue = 10;

#[derive(JamEncode)]
pub struct IsAuthorizedArgs {
    work_package: WorkPackage, // p
    core_index: CoreIndex,     // c
}

/// `Ψ_M` invocation function arguments
#[derive(JamEncode)]
pub struct RefineVMArgs {
    /// Associated service index (`s` of `WorkItem`)
    refine_address: Address,
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

pub enum AccumulateResult {
    Result(Box<AccumulateHostContext>, Option<Hash32>), // (mutated context, optional result hash)
    Unchanged,
}

#[allow(dead_code)]
struct BalanceChangeSet {
    recipient: Address,
    added_amount: Balance,
}

// TODO: impl
pub struct DestinationStorageChangeSet {}

#[allow(dead_code)]
#[derive(Default)]
pub struct OnTransferResult {
    balance_change_set: Option<BalanceChangeSet>,
    storage_change_set: Option<DestinationStorageChangeSet>,
}

impl OnTransferResult {
    pub fn new(
        recipient: Address,
        added_amount: Balance,
        storage_change_set: DestinationStorageChangeSet,
    ) -> Self {
        Self {
            balance_change_set: Some(BalanceChangeSet {
                recipient,
                added_amount,
            }),
            storage_change_set: Some(storage_change_set),
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
        state_manager: &StateManager,
        args: &IsAuthorizedArgs,
    ) -> Result<WorkExecutionOutput, PVMError> {
        // retrieve the service account code via the historical lookup function
        let code = match state_manager
            .lookup_preimage(
                args.work_package.authorizer_address,
                &Timeslot::new(args.work_package.context.lookup_anchor_timeslot),
                &args.work_package.authorizer.auth_code_hash,
            )
            .await?
        {
            Some(code) => code,
            None => {
                // failed to get the is_authorized code from the service account
                return Ok(WorkExecutionOutput::bad());
            }
        };

        let common_invocation_result = PVM::invoke_with_args(
            state_manager,
            args.work_package.authorizer_address,
            &code,
            IS_AUTHORIZED_INITIAL_PC,
            IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
            &args.encode()?,
            &mut InvocationContext::X_I, // not used
        )
        .await?;

        match common_invocation_result {
            CommonInvocationResult::OutOfGas(_) => Ok(WorkExecutionOutput::out_of_gas()),
            CommonInvocationResult::Panic(_) => Ok(WorkExecutionOutput::panic()),
            CommonInvocationResult::Result(output) => Ok(WorkExecutionOutput::ok(output)),
            CommonInvocationResult::ResultUnavailable(_) => Ok(WorkExecutionOutput::ok_empty()),
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
        state_manager: &StateManager,
        args: RefineInvokeArgs,
    ) -> Result<RefineResult, PVMError> {
        let work_item = &args.package.work_items.clone()[args.item_idx];

        // Check the account to run refinement exists in the global state
        let refine_account_exists = !state_manager
            .account_exists(work_item.service_index)
            .await?;

        // Retrieve the service account code via the historical lookup function
        let maybe_code = state_manager
            .lookup_preimage(
                work_item.service_index,
                &Timeslot(args.package.context.lookup_anchor_timeslot),
                &work_item.service_code_hash,
            )
            .await?;

        if !refine_account_exists || maybe_code.is_none() {
            return Ok(RefineResult::bad());
        }

        let code = maybe_code.expect("Confirmed code exists");
        if code.len() > MAX_SERVICE_CODE_SIZE {
            return Ok(RefineResult::big());
        }

        let vm_args = RefineVMArgs {
            refine_address: work_item.service_index,
            work_payload: work_item.payload_blob.clone().into_vec(),
            work_package_hash: args.package.hash()?,
            refinement_context: args.package.context.clone(),
            auth_code_hash: args.package.authorizer.auth_code_hash,
        };

        let mut context = InvocationContext::X_R(RefineHostContext::new_with_invoke_args(args));
        let common_invocation_result = PVM::invoke_with_args(
            state_manager,
            work_item.service_index,
            &code,
            REFINE_INITIAL_PC,
            work_item.refine_gas_limit,
            &vm_args.encode()?,
            &mut context,
        )
        .await?;

        let RefineHostContext {
            export_segments, ..
        } = if let InvocationContext::X_R(context) = context {
            context
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match common_invocation_result {
            CommonInvocationResult::Result(output) => Ok(RefineResult::ok(output, export_segments)),
            CommonInvocationResult::ResultUnavailable(_) => {
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
    /// * `accumulate_address` - The address of the target service account to run the accumulation process
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation process
    /// * `operands` - A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Ψ_A` of the GP
    pub async fn accumulate(
        state_manager: &StateManager,
        accumulate_address: Address,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulateOperand>,
    ) -> Result<AccumulateResult, PVMError> {
        let code = state_manager.get_account_code(accumulate_address).await?;

        if code.is_none() {
            return Ok(AccumulateResult::Unchanged);
        }
        let code = code.unwrap();

        let current_entropy = state_manager.get_entropy_accumulator().await?.current();
        let current_timeslot = state_manager.get_timeslot().await?;
        let accumulate_context = AccumulateHostContext::new(
            state_manager,
            accumulate_address,
            current_entropy,
            &current_timeslot,
        )
        .await?;

        let context_pair = AccumulateHostContextPair {
            x: Box::new(accumulate_context.clone()),
            y: Box::new(accumulate_context),
        };

        let mut context = InvocationContext::X_A(context_pair);

        // TODO: Accounts subject to mutation due to `read`, `write` and `lookup` host functions must be copied into the partial state (Function G)
        // TODO: use `AccumulateHostContext::copy_account_to_partial_state_sandbox`, and host functions must return the subject account addresses.
        let common_invocation_result = PVM::invoke_with_args(
            state_manager,
            accumulate_address,
            &code,
            ACCUMULATE_INITIAL_PC,
            gas_limit,
            &operands.encode()?,
            &mut context,
        )
        .await?;

        let AccumulateHostContextPair { x, y } = if let InvocationContext::X_A(pair) = context {
            pair
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match common_invocation_result {
            CommonInvocationResult::Result(output)
            | CommonInvocationResult::ResultUnavailable(output) => {
                Ok(AccumulateResult::Result(x, octets_to_hash32(&output)))
            }
            CommonInvocationResult::OutOfGas(_) | CommonInvocationResult::Panic(_) => {
                Ok(AccumulateResult::Result(y, None))
            }
        }
    }

    /// OnTransfer invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - State manager to access to the global state
    /// * `destination` - The recipient address of the transfers
    /// * `transfers` - The deferred transfers
    ///
    /// Represents `Ψ_T` of the GP
    pub async fn on_transfer(
        state_manager: &StateManager,
        destination: Address,
        transfers: Vec<DeferredTransfer>,
    ) -> Result<OnTransferResult, PVMError> {
        let total_amount = transfers.iter().map(|t| t.amount).sum();
        let total_gas_limit = transfers.iter().map(|t| t.gas_limit).sum();

        let code = state_manager.get_account_code(destination).await?;
        if code.is_none() || transfers.is_empty() {
            return Ok(OnTransferResult::default());
        }
        let code = code.unwrap();

        let on_transfer_context = OnTransferHostContext::new(state_manager, destination).await?;

        let _common_invocation_result = PVM::invoke_with_args(
            state_manager,
            destination,
            &code,
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &transfers.encode()?,
            &mut InvocationContext::X_T(on_transfer_context), // not used
        )
        .await?;

        // TODO: return the recipient account storage changeset
        Ok(OnTransferResult::new(
            destination,
            total_amount,
            DestinationStorageChangeSet {},
        ))
    }
}
