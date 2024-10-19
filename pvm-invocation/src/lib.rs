pub mod accumulation;

use rjam_codec::JamEncode;
use rjam_common::{
    Address, Balance, DeferredTransfer, Hash32, Octets, RefinementContext, UnsignedGas,
    WorkExecutionError, WorkExecutionOutput, WorkPackage, MAX_SERVICE_CODE_SIZE,
};
use rjam_crypto::utils::octets_to_hash32;
use rjam_host_interface::contexts::{
    AccumulateContext, AccumulateContextPair, InvocationContext, RefineContext,
};
use rjam_pvm::{CommonInvocationResult, PVM};
use rjam_pvm_core::{
    state::memory::MemAddress,
    types::{
        accumulation::AccumulateOperand,
        common::ExportDataSegment,
        error::{HostCallError::InvalidContext, PVMError},
    },
};
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::state::timeslot::Timeslot;

const IS_AUTHORIZED_INITIAL_PC: MemAddress = 0;
const REFINE_INITIAL_PC: MemAddress = 5;
const ACCUMULATE_INITIAL_PC: MemAddress = 10;
const ON_TRANSFER_INITIAL_PC: MemAddress = 15;

pub struct RefineResult {
    output: WorkExecutionOutput,
    export_segments: Vec<ExportDataSegment>,
}

pub enum AccumulateResult {
    Unchanged,
    Result(AccumulateContext, Option<Hash32>), // (mutated context, optional result hash)
}

struct PVMInvocation;

impl PVMInvocation {
    //
    // PVM invocation entry-points
    //

    pub fn is_authorized(
        state_manager: &StateManager, // FIXME: not needed
        work_package: WorkPackage,
        core_index: u32,
    ) -> Result<WorkExecutionOutput, PVMError> {
        // retrieve the service account code via the historical lookup function
        let code = match state_manager.lookup_preimage(
            work_package.authorizer_address,
            &Timeslot(work_package.context.lookup_anchor_timeslot),
            &work_package.auth_code_hash,
        )? {
            Some(code) => code,
            None => {
                // TODO: check return type for this case
                return Ok(WorkExecutionOutput::Error(
                    WorkExecutionError::ServiceCodeLookupError,
                ));
            }
        };

        let is_authorized_gas_limit = 0; // FIXME: not specified in the GP

        let mut args = vec![];
        work_package.encode_to(&mut args)?;
        core_index.encode_to(&mut args)?;

        let common_invocation_result = PVM::common_invocation(
            state_manager,
            work_package.authorizer_address,
            &code,
            IS_AUTHORIZED_INITIAL_PC,
            is_authorized_gas_limit,
            &args,
            &mut InvocationContext::X_I, // TODO: better handling (not used)
        )?;

        match common_invocation_result {
            CommonInvocationResult::OutOfGas(_) => {
                Ok(WorkExecutionOutput::Error(WorkExecutionError::OutOfGas))
            }
            CommonInvocationResult::Failure(_) => Ok(WorkExecutionOutput::Error(
                WorkExecutionError::UnexpectedTermination,
            )),
            CommonInvocationResult::Result((_gas, output))
            | CommonInvocationResult::ResultUnavailable((_gas, output)) => {
                Ok(WorkExecutionOutput::Output(output))
            }
        }
    }

    pub fn refine(
        state_manager: &StateManager, // FIXME: not needed
        code_hash: Hash32,
        gas_limit: UnsignedGas,
        account_address: Address,
        work_package_hash: Hash32,
        work_payload: Octets,
        refinement_context: RefinementContext,
        authorizer_hash: Hash32,
        authorization_output: Octets,
        import_segments: Vec<ExportDataSegment>,
        extrinsic_data_blobs: Vec<Octets>,
        export_segment_offset: usize,
    ) -> Result<RefineResult, PVMError> {
        // retrieve the service account code via the historical lookup function
        let code = match state_manager.lookup_preimage(
            account_address,
            &Timeslot(refinement_context.lookup_anchor_timeslot),
            &code_hash,
        )? {
            Some(code) => code,
            None => {
                // TODO: check return type for this case
                return Ok(RefineResult {
                    output: WorkExecutionOutput::Error(WorkExecutionError::ServiceCodeLookupError),
                    export_segments: vec![],
                });
            }
        };

        if code.len() > MAX_SERVICE_CODE_SIZE {
            return Ok(RefineResult {
                output: WorkExecutionOutput::Error(WorkExecutionError::CodeSizeExceeded),
                export_segments: vec![],
            });
        }

        // encode arguments for the refinement process
        let mut args = vec![];
        account_address.encode_to(&mut args)?;
        work_payload.encode_to(&mut args)?;
        work_package_hash.encode_to(&mut args)?;
        refinement_context.encode_to(&mut args)?;
        authorizer_hash.encode_to(&mut args)?;
        authorization_output.encode_to(&mut args)?;
        extrinsic_data_blobs.encode_to(&mut args)?;

        let mut context = InvocationContext::X_R(RefineContext::default());

        let common_invocation_result = PVM::common_invocation(
            state_manager,
            account_address,
            &code,
            REFINE_INITIAL_PC,
            gas_limit,
            &args,
            &mut context,
        )?;

        let RefineContext {
            export_segments, ..
        } = if let InvocationContext::X_R(context) = context {
            context
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match common_invocation_result {
            CommonInvocationResult::Result((_gas, output))
            | CommonInvocationResult::ResultUnavailable((_gas, output)) => Ok(RefineResult {
                output: WorkExecutionOutput::Output(output),
                export_segments,
            }),
            CommonInvocationResult::OutOfGas(_) => Ok(RefineResult {
                output: WorkExecutionOutput::Error(WorkExecutionError::OutOfGas),
                export_segments: vec![],
            }),
            CommonInvocationResult::Failure(_) => Ok(RefineResult {
                output: WorkExecutionOutput::Error(WorkExecutionError::UnexpectedTermination),
                export_segments: vec![],
            }),
        }
    }

    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `service_manager` - State manager to access to the state cache values
    /// * `target_address` - The address of the target service account to run the accumulation process
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation operation
    /// * `operands` - A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Psi_A` of the GP
    pub fn accumulate(
        state_manager: &StateManager,
        target_address: Address,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulateOperand>,
    ) -> Result<AccumulateResult, PVMError> {
        let code = state_manager.get_account_code(target_address)?;

        if operands.is_empty() || code.is_none() {
            return Ok(AccumulateResult::Unchanged);
        }
        let code = code.unwrap();

        let current_entropy = state_manager.get_entropy_accumulator()?.current();
        let current_timeslot = state_manager.get_timeslot()?;
        let accumulate_context = AccumulateContext::new(
            state_manager,
            target_address,
            current_entropy,
            &current_timeslot,
        )?;

        let context_pair = AccumulateContextPair {
            x: accumulate_context.clone(),
            y: accumulate_context,
        };

        let mut context = InvocationContext::X_A(context_pair);

        // initialize the new account address in-memory state (part of Accumulate context)

        // TODO: Used gas accumulation handling
        let common_invocation_result = PVM::common_invocation(
            state_manager,
            target_address,
            &code,
            ACCUMULATE_INITIAL_PC,
            gas_limit,
            &operands.encode()?,
            &mut context,
        )?;

        let AccumulateContextPair { x, y } = if let InvocationContext::X_A(pair) = context {
            pair
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        match common_invocation_result {
            CommonInvocationResult::Result((_gas, output))
            | CommonInvocationResult::ResultUnavailable((_gas, output)) => {
                Ok(AccumulateResult::Result(x, octets_to_hash32(&output)))
            }

            CommonInvocationResult::OutOfGas(_) | CommonInvocationResult::Failure(_) => {
                Ok(AccumulateResult::Result(y, None))
            }
        }
    }

    pub fn on_transfer(
        state_manager: &StateManager,
        destination_address: Address,
        transfers: Vec<DeferredTransfer>,
    ) -> Result<(), PVMError> {
        let total_amount: Balance = transfers.iter().map(|t| t.amount).sum();

        state_manager.with_mut_account_metadata(
            StateWriteOp::Update,
            destination_address,
            |account| {
                account.account_info.balance += total_amount;
            },
        )?;

        let code = state_manager.get_account_code(destination_address)?;
        if code.is_none() || transfers.is_empty() {
            return Ok(());
        }
        let code = code.unwrap();

        let total_gas_limit = transfers.iter().map(|t| t.gas_limit).sum();

        // TODO: check the return type
        PVM::common_invocation(
            state_manager,
            destination_address,
            &code,
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &transfers.encode()?,
            &mut InvocationContext::X_T, // TODO: better handling (not used)
        )?;

        // TODO: check return type (service account context)
        Ok(())
    }
}
