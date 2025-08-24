pub(crate) mod auditable_bundle;
pub(crate) mod avail_spec;
pub mod pipeline;

use crate::error::PVMInvokeError;
use fr_codec::prelude::*;
use fr_common::{
    workloads::{RefinementContext, WorkExecutionResult},
    CodeHash, Octets, ServiceId, UnsignedGas, WorkPackageHash, MAX_SERVICE_CODE_SIZE,
};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_host::{
    context::{InvocationContext, RefineHostContext},
    error::HostCallError::InvalidContext,
};
use fr_pvm_interface::invoke::{PVMInterface, PVMInvocationOutput};
use fr_pvm_types::{
    common::ExportDataSegment, constants::REFINE_INITIAL_PC, invoke_args::RefineInvokeArgs,
};
use fr_state::manager::StateManager;
use std::sync::Arc;

/// `Ψ_M` invocation function arguments for `Ψ_R`
#[derive(JamEncode)]
struct RefineVMArgs {
    /// Associated service id (`s` of `WorkItem`)
    service_id: ServiceId,
    /// Work item payload blob (**`y`** of `WorkItem`)
    work_payload: Vec<u8>,
    /// Work package hash (Hash of `WorkPackage`)
    work_package_hash: WorkPackageHash,
    /// Refinement context (**`c`** of `WorkPackage`)
    refinement_context: RefinementContext,
    /// Authorizer code hash (`u` of `WorkPackage`)
    auth_code_hash: CodeHash,
}

pub struct RefineResult {
    /// `u`: Gas used during `refine` execution.
    pub gas_used: UnsignedGas,
    /// `r`: Refine result output.
    pub output: WorkExecutionResult,
    /// **`e`**: Data segments exported by the `refine` execution.
    pub export_segments: Vec<ExportDataSegment>,
}

impl RefineResult {
    pub fn ok(
        gas_used: UnsignedGas,
        output: Vec<u8>,
        export_segments: Vec<ExportDataSegment>,
    ) -> Self {
        Self {
            gas_used,
            output: WorkExecutionResult::Output(Octets::from_vec(output)),
            export_segments,
        }
    }

    pub fn ok_empty(gas_used: UnsignedGas, export_segments: Vec<ExportDataSegment>) -> Self {
        Self {
            gas_used,
            output: WorkExecutionResult::ok_empty(),
            export_segments,
        }
    }

    pub fn bad() -> Self {
        Self {
            gas_used: 0,
            output: WorkExecutionResult::bad(),
            export_segments: vec![],
        }
    }

    pub fn big() -> Self {
        Self {
            gas_used: 0,
            output: WorkExecutionResult::big(),
            export_segments: vec![],
        }
    }

    pub fn out_of_gas(gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: WorkExecutionResult::out_of_gas(),
            export_segments: vec![],
        }
    }

    pub fn panic(gas_used: UnsignedGas) -> Self {
        Self {
            gas_used,
            output: WorkExecutionResult::panic(),
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
    ) -> Result<RefineResult, PVMInvokeError> {
        tracing::info!("Ψ_R (refine) invoked.");

        let Some(work_item) = args.package.work_items.as_slice().get(args.item_idx) else {
            tracing::warn!("Invalid work item index.");
            return Ok(RefineResult::bad());
        };

        // Check the service account to run refinement exists in the global state
        let service_exists = state_manager.account_exists(work_item.service_id).await?;
        if !service_exists {
            tracing::warn!("Service account associated with the refinement not found.");
            return Ok(RefineResult::bad());
        }

        // Retrieve the service account code via the historical lookup function
        let Some(account_code) = state_manager
            .get_account_code_by_lookup(
                work_item.service_id,
                args.package.context.lookup_anchor_timeslot,
                &work_item.service_code_hash,
            )
            .await?
        else {
            // Failed to get the `refine` code from the service account
            tracing::warn!("Refine service code not found.");
            return Ok(RefineResult::bad());
        };

        if account_code.code().len() > MAX_SERVICE_CODE_SIZE {
            tracing::warn!("Refine service code exceeds maximum allowed.");
            return Ok(RefineResult::big());
        }

        let vm_args = RefineVMArgs {
            service_id: work_item.service_id,
            work_payload: work_item.payload_blob.clone().into_vec(),
            work_package_hash: hash::<Blake2b256>(&args.package.encode()?)?,
            refinement_context: args.package.context.clone(),
            auth_code_hash: args.package.auth_code_hash.clone(),
        };

        let mut refine_ctx =
            InvocationContext::X_R(RefineHostContext::new_with_invoke_args(args.clone()));
        let result = PVMInterface::invoke_with_args(
            state_manager,
            work_item.service_id,
            account_code.code(),
            REFINE_INITIAL_PC,
            work_item.refine_gas_limit,
            &vm_args.encode()?,
            &mut refine_ctx,
            None,
        )
        .await?;

        let RefineHostContext {
            export_segments, ..
        } = if let InvocationContext::X_R(x) = refine_ctx {
            x
        } else {
            return Err(PVMInvokeError::HostCallError(InvalidContext));
        };

        match result.output {
            PVMInvocationOutput::Output(output) => {
                Ok(RefineResult::ok(result.gas_used, output, export_segments))
            }
            PVMInvocationOutput::OutputUnavailable => {
                Ok(RefineResult::ok_empty(result.gas_used, export_segments))
            }
            PVMInvocationOutput::OutOfGas(_) => Ok(RefineResult::out_of_gas(result.gas_used)),
            PVMInvocationOutput::Panic(_) => Ok(RefineResult::panic(result.gas_used)),
        }
    }
}
