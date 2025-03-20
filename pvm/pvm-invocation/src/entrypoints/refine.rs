use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{
    workloads::{RefinementContext, WorkExecutionOutput},
    Hash32, Octets, ServiceId, MAX_SERVICE_CODE_SIZE,
};
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_host::{
    context::{InvocationContext, RefineHostContext},
    error::HostCallError::InvalidContext,
};
use rjam_pvm_interface::{
    error::PVMError,
    invoke::{PVMInterface, PVMInvocationResult},
};
use rjam_pvm_types::{
    common::ExportDataSegment, constants::REFINE_INITIAL_PC, invoke_args::RefineInvokeArgs,
};
use rjam_state::manager::StateManager;
use std::sync::Arc;

/// `Ψ_M` invocation function arguments for `Ψ_R`
#[derive(JamEncode)]
struct RefineVMArgs {
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

pub struct RefineInvocation;
impl RefineInvocation {
    /// Refine invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - A handle to a `StateManager` to access to the global state. The only allowed access is the historical lookup.
    /// * `args` - Refine entry-point function arguments.
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
            work_package_hash: hash::<Blake2b256>(&args.package.encode()?)?,
            refinement_context: args.package.context.clone(),
            auth_code_hash: args.package.authorizer.auth_code_hash,
        };

        let mut refine_ctx =
            InvocationContext::X_R(RefineHostContext::new_with_invoke_args(args.clone()));
        let result = PVMInterface::invoke_with_args(
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
            PVMInvocationResult::Result(output) => Ok(RefineResult::ok(output, export_segments)),
            PVMInvocationResult::ResultUnavailable => Ok(RefineResult::ok_empty(export_segments)),
            PVMInvocationResult::OutOfGas(_) => Ok(RefineResult::out_of_gas()),
            PVMInvocationResult::Panic(_) => Ok(RefineResult::panic()),
        }
    }
}
