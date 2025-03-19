use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{
    workloads::{WorkExecutionOutput, WorkPackage},
    CoreIndex, IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
};
use rjam_pvm_core::types::{common::RegValue, error::PVMError};
use rjam_pvm_host::context::InvocationContext;
use rjam_pvm_interface::{CommonInvocationResult, PVM};
use rjam_state::manager::StateManager;
use std::sync::Arc;

const IS_AUTHORIZED_INITIAL_PC: RegValue = 0;

#[derive(JamEncode)]
pub struct IsAuthorizedArgs {
    /// **`p`**: Work package
    pub package: WorkPackage,
    /// `c`: Core index to process the work package
    pub core_index: CoreIndex,
}

pub struct IsAuthorizedInvocation;
impl IsAuthorizedInvocation {
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
}
