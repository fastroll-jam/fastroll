use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{
    workloads::{WorkExecutionOutput, WorkPackage},
    CoreIndex, UnsignedGas, IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
};
use rjam_pvm_host::context::InvocationContext;
use rjam_pvm_interface::{
    error::PVMError,
    invoke::{PVMInterface, PVMInvocationResult},
};
use rjam_pvm_types::constants::IS_AUTHORIZED_INITIAL_PC;
use rjam_state::manager::StateManager;
use std::sync::Arc;

#[derive(JamEncode)]
pub struct IsAuthorizedArgs {
    /// **`p`**: Work package
    pub package: WorkPackage,
    /// `c`: Core index to process the work package
    pub core_index: CoreIndex,
}

pub struct IsAuthorizedResult {
    pub gas_used: UnsignedGas,
    pub work_execution_output: WorkExecutionOutput,
}

impl From<PVMInvocationResult> for IsAuthorizedResult {
    fn from(result: PVMInvocationResult) -> Self {
        Self {
            gas_used: result.gas_used,
            work_execution_output: WorkExecutionOutput::from(result.output),
        }
    }
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
    ) -> Result<IsAuthorizedResult, PVMError> {
        // retrieve the service account code via historical lookup
        let Some(account_code) = state_manager
            .get_account_code_by_lookup(
                args.package.authorizer_service_id,
                args.package.context.lookup_anchor_timeslot,
                &args.package.authorizer.auth_code_hash,
            )
            .await?
        else {
            // failed to get the `is_authorized` code from the service account
            return Ok(IsAuthorizedResult {
                gas_used: 0,
                work_execution_output: WorkExecutionOutput::bad(),
            });
        };

        let result = PVMInterface::invoke_with_args(
            state_manager,
            args.package.authorizer_service_id,
            account_code.code(),
            IS_AUTHORIZED_INITIAL_PC,
            IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
            &args.encode()?,
            &mut InvocationContext::X_I, // not used
        )
        .await?;

        Ok(IsAuthorizedResult::from(result))
    }
}
