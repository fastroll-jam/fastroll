pub mod accumulation;

use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::*;
use rjam_crypto::octets_to_hash32;
use rjam_pvm::{CommonInvocationResult, PVM};
use rjam_pvm_core::types::{
    accumulation::AccumulateOperand,
    common::{ExportDataSegment, RegValue},
    error::{HostCallError::InvalidContext, PVMError},
};
use rjam_pvm_hostcall::contexts::*;
use rjam_state::{StateManager, StateWriteOp};
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

// Gas Allocations
pub const ACCUMULATION_GAS_PER_CORE: UnsignedGas = 100_000; // G_A
pub const ACCUMULATION_GAS_ALL_CORES: UnsignedGas = 341_000_000; // G_T
pub const IS_AUTHORIZED_GAS_PER_WORK_PACKAGE: UnsignedGas = 1_000_000; // G_I
pub const REFINE_GAS_PER_WORK_PACKAGE: UnsignedGas = 500_000_000; // G_R

#[derive(JamEncode)]
pub struct IsAuthorizedArgs {
    work_package: WorkPackage, // p
    core_index: CoreIndex,     // c
}

#[derive(JamEncode)]
pub struct RefineArgs {
    refine_address: Address,               // s
    work_payload: Vec<u8>,                 // y
    work_package_hash: Hash32,             // p
    refinement_context: RefinementContext, // c
    authorizer_hash: Hash32,               // a
    authorization_output: Vec<u8>,         // o
    extrinsic_data_blobs: Vec<Vec<u8>>,    // x_bar
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
    Unchanged,
    Result(Box<AccumulateHostContext>, Option<Hash32>), // (mutated context, optional result hash)
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
    /// * `state_manager` - State manager to access to the state cache values. This is only used for the code data lookup.
    /// * `args` - IsAuthorized arguments
    ///
    /// Represents `Ψ_I` of the GP
    pub fn is_authorized(
        state_manager: &StateManager,
        args: &IsAuthorizedArgs,
    ) -> Result<WorkExecutionOutput, PVMError> {
        // retrieve the service account code via the historical lookup function
        let code = match state_manager.lookup_preimage(
            args.work_package.authorizer_address,
            &Timeslot::new(args.work_package.context.lookup_anchor_timeslot),
            &args.work_package.authorizer.auth_code_hash,
        )? {
            Some(code) => code,
            None => {
                // failed to get the is_authorized code from the service account
                return Ok(WorkExecutionOutput::bad());
            }
        };

        let common_invocation_result = PVM::common_invocation(
            state_manager,
            args.work_package.authorizer_address,
            &code,
            IS_AUTHORIZED_INITIAL_PC,
            IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
            &args.encode()?,
            &mut InvocationContext::X_I, // not used
        )?;

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
    /// * `state_manager` - State manager to access to the state cache values. The only allowed access is the historical lookup.
    /// * `code_hash` - Prediction of the refinement service code hash at the time of reporting
    /// * `args` - Refinement arguments
    /// * `gas_limit` - The maximum amount of gas allowed for the refinement process
    /// * `import_segments` - Fixed-length data segments imported from the import DA
    /// * `export_segments_offset` - Initial offset index of the export segments array
    ///
    /// Represents `Ψ_R` of the GP
    pub fn refine(
        state_manager: &StateManager,
        code_hash: Hash32,
        gas_limit: UnsignedGas,
        args: &RefineArgs,
        import_segments: Vec<ExportDataSegment>,
        export_segments_offset: usize,
    ) -> Result<RefineResult, PVMError> {
        // check the refine target account address exists in the global state
        let refine_account_exists = !state_manager.account_exists(args.refine_address)?;

        // retrieve the service account code via the historical lookup function
        let maybe_code = state_manager.lookup_preimage(
            args.refine_address,
            &Timeslot(args.refinement_context.lookup_anchor_timeslot),
            &code_hash,
        )?;

        if !refine_account_exists || maybe_code.is_none() {
            return Ok(RefineResult::bad());
        }

        let code = maybe_code.unwrap();

        if code.len() > MAX_SERVICE_CODE_SIZE {
            return Ok(RefineResult::big());
        }

        let mut context = InvocationContext::X_R(RefineHostContext::new(
            args.refinement_context.lookup_anchor_timeslot,
            import_segments,
            export_segments_offset,
        ));

        let common_invocation_result = PVM::common_invocation(
            state_manager,
            args.refine_address,
            &code,
            REFINE_INITIAL_PC,
            gas_limit,
            &args.encode()?,
            &mut context,
        )?;

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
    /// * `state_manager` - State manager to access to the state cache values
    /// * `accumulate_address` - The address of the target service account to run the accumulation process
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation process
    /// * `operands` - A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Ψ_A` of the GP
    pub fn accumulate(
        state_manager: &StateManager,
        accumulate_address: Address,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulateOperand>,
    ) -> Result<AccumulateResult, PVMError> {
        let code = state_manager.get_account_code(accumulate_address)?;

        if operands.is_empty() || code.is_none() {
            return Ok(AccumulateResult::Unchanged);
        }
        let code = code.unwrap();

        let current_entropy = state_manager.get_entropy_accumulator()?.current();
        let current_timeslot = state_manager.get_timeslot()?;
        let accumulate_context = AccumulateHostContext::new(
            state_manager,
            accumulate_address,
            current_entropy,
            &current_timeslot,
        )?;

        let context_pair = AccumulateHostContextPair {
            x: Box::new(accumulate_context.clone()),
            y: Box::new(accumulate_context),
        };

        let mut context = InvocationContext::X_A(context_pair);

        // initialize the new account address in-memory state (part of Accumulate context)

        // TODO: Used gas accumulation handling
        let common_invocation_result = PVM::common_invocation(
            state_manager,
            accumulate_address,
            &code,
            ACCUMULATE_INITIAL_PC,
            gas_limit,
            &operands.encode()?,
            &mut context,
        )?;

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
    /// * `state_manager` - State manager to access to the state cache values
    /// * `destination` - The recipient address of the transfers
    /// * `transfers` - The deferred transfers
    ///
    /// Represents `Ψ_T` of the GP
    pub fn on_transfer(
        state_manager: &StateManager,
        destination: Address,
        transfers: Vec<DeferredTransfer>,
    ) -> Result<(), PVMError> {
        let total_amount: Balance = transfers.iter().map(|t| t.amount).sum();

        state_manager.with_mut_account_metadata(StateWriteOp::Update, destination, |account| {
            account.account_info.balance += total_amount;
        })?;

        let code = state_manager.get_account_code(destination)?;
        if code.is_none() || transfers.is_empty() {
            return Ok(());
        }
        let code = code.unwrap();

        let total_gas_limit = transfers.iter().map(|t| t.gas_limit).sum();

        // TODO: check the return type
        PVM::common_invocation(
            state_manager,
            destination,
            &code,
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &transfers.encode()?,
            &mut InvocationContext::X_T, // not used
        )?;

        // TODO: check return type (service account context)
        Ok(())
    }
}
