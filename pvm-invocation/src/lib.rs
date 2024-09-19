use jam_codec::JamEncode;
use jam_common::{
    AccountAddress, Hash32, Octets, RefinementContext, RefinementErrors, RefinementOutput,
    UnsignedGas, MAX_SERVICE_CODE_SIZE,
};
use jam_crypto::utils::octets_to_hash32;
use jam_host_interface::contexts::{
    AccumulateContext, AccumulateContextPair, InvocationContext, RefineContext,
};
use jam_pvm::{CommonInvocationResult, PVM};
use jam_pvm_core::{
    state::memory::MemAddress,
    types::{
        accumulation::AccumulateOperand,
        common::ExportDataSegment,
        error::{
            HostCallError::{AccountNotFound, InvalidContext},
            PVMError,
        },
    },
};
use jam_state::cache::STATE_CACHE;
use jam_types::state::{services::ServiceAccounts, timeslot::Timeslot};

const IS_AUTHORIZED_INITIAL_PC: MemAddress = 0;
const REFINE_INITIAL_PC: MemAddress = 5;
const ACCUMULATE_INITIAL_PC: MemAddress = 10;
const ON_TRANSFER_INITIAL_PC: MemAddress = 15;

pub enum AccumulateResult {
    Unchanged,
    Result(AccumulateContext, Option<Hash32>), // (mutated context, optional result hash)
}

pub struct RefineResult {
    output: RefinementOutput,
    export_segments: Vec<ExportDataSegment>,
}

struct PVMInvocation;

impl PVMInvocation {
    //
    // PVM invocation entry-points
    //

    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `service_accounts` - The current global state of service accounts, after preimage integration but before accumulation
    /// * `target_address` - The address of the target service account to run the accumulation process
    /// * `gas_limit` - The maximum amount of gas allowed for the accumulation operation
    /// * `operands` - A vector of `AccumulateOperand`s, which are the outputs from the refinement process to be accumulated
    ///
    /// Represents `Psi_A` of the GP
    pub fn accumulate(
        service_accounts: &ServiceAccounts,
        target_address: AccountAddress,
        gas_limit: UnsignedGas,
        operands: Vec<AccumulateOperand>,
    ) -> Result<AccumulateResult, PVMError> {
        let target_account = service_accounts
            .get_account(&target_address)
            .ok_or(PVMError::HostCallError(AccountNotFound))?
            .clone();

        let code = target_account.get_code().cloned();

        if operands.is_empty() || code.is_none() {
            return Ok(AccumulateResult::Unchanged);
        }

        // `x` for a regular dimension and `y` for an exceptional dimension
        let context_pair = AccumulateContextPair {
            x: AccumulateContext::initialize_context(
                service_accounts,
                &target_account,
                target_address,
            )?,
            y: AccumulateContext::initialize_context(
                service_accounts,
                &target_account,
                target_address,
            )?,
        };

        let mut context = InvocationContext::X_A(context_pair);

        let common_invocation_result = PVM::common_invocation(
            target_address,
            &code.unwrap()[..],
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
                Ok(AccumulateResult::Result(x, octets_to_hash32(output)))
            }

            CommonInvocationResult::OutOfGas(_) | CommonInvocationResult::Failure(_) => {
                Ok(AccumulateResult::Result(y, None))
            }
        }
    }

    pub fn refine(
        code_hash: Hash32,
        gas_limit: UnsignedGas,
        service_index: AccountAddress,
        work_package_hash: Hash32,
        work_payload: Octets,
        refinement_context: RefinementContext,
        authorizer_hash: Hash32,
        authorization_output: Octets,
        import_segments: Vec<ExportDataSegment>,
        extrinsic_data_blobs: Vec<Octets>,
        export_segment_offset: usize,
    ) -> Result<RefineResult, PVMError> {
        let service_accounts = STATE_CACHE.get_service_accounts_cache()?.unwrap();

        let refine_code = match service_accounts
            .get_account(&service_index)
            .and_then(|account| {
                account.lookup_preimage(
                    &Timeslot(refinement_context.lookup_anchor_timeslot),
                    code_hash,
                )
            }) {
            Some(code) => code,
            None => {
                return Ok(RefineResult {
                    output: RefinementOutput::Error(RefinementErrors::ServiceCodeLookupError),
                    export_segments: vec![],
                })
            }
        };

        if refine_code.len() > MAX_SERVICE_CODE_SIZE {
            return Ok(RefineResult {
                output: RefinementOutput::Error(RefinementErrors::CodeSizeExceeded),
                export_segments: vec![],
            });
        }

        // encode arguments for the refinement process
        let mut refine_args = vec![];
        service_index.encode_to(&mut refine_args)?;
        work_payload.encode_to(&mut refine_args)?;
        work_package_hash.encode_to(&mut refine_args)?;
        refinement_context.encode_to(&mut refine_args)?;
        authorizer_hash.encode_to(&mut refine_args)?;
        authorization_output.encode_to(&mut refine_args)?;
        extrinsic_data_blobs.encode_to(&mut refine_args)?;

        let mut context = InvocationContext::X_R(RefineContext::default());

        let common_invocation_result = PVM::common_invocation(
            service_index,
            &refine_code[..],
            REFINE_INITIAL_PC,
            gas_limit,
            &refine_args[..],
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
                output: RefinementOutput::Output(output),
                export_segments,
            }),
            CommonInvocationResult::OutOfGas(_) => Ok(RefineResult {
                output: RefinementOutput::Error(RefinementErrors::OutOfGas),
                export_segments: vec![],
            }),
            CommonInvocationResult::Failure(_) => Ok(RefineResult {
                output: RefinementOutput::Error(RefinementErrors::UnexpectedTermination),
                export_segments: vec![],
            }),
        }
    }
}
