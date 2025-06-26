use fr_codec::prelude::*;
use fr_common::{
    workloads::WorkExecutionResult, CoreIndex, UnsignedGas, IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
    MAX_IS_AUTHORIZED_CODE_SIZE,
};
use fr_pvm_host::context::{InvocationContext, IsAuthorizedHostContext};
use fr_pvm_interface::{
    error::PVMError,
    invoke::{PVMInterface, PVMInvocationResult},
};
use fr_pvm_types::{constants::IS_AUTHORIZED_INITIAL_PC, invoke_args::IsAuthorizedInvokeArgs};
use fr_state::manager::StateManager;
use std::sync::Arc;

/// `Ψ_M` invocation function arguments for `Ψ_I`
struct IsAuthorizedVmArgs {
    /// `c`: Core index to process the work package
    pub core_index: CoreIndex,
}

impl JamEncode for IsAuthorizedVmArgs {
    fn size_hint(&self) -> usize {
        2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.core_index.encode_to_fixed(dest, 2)
    }
}

pub struct IsAuthorizedResult {
    pub gas_used: UnsignedGas,
    pub work_execution_result: WorkExecutionResult,
}

impl From<PVMInvocationResult> for IsAuthorizedResult {
    fn from(result: PVMInvocationResult) -> Self {
        Self {
            gas_used: result.gas_used,
            work_execution_result: WorkExecutionResult::from(result.output),
        }
    }
}

impl IsAuthorizedResult {
    pub fn bad() -> Self {
        Self {
            gas_used: 0,
            work_execution_result: WorkExecutionResult::bad(),
        }
    }

    pub fn big() -> Self {
        Self {
            gas_used: 0,
            work_execution_result: WorkExecutionResult::big(),
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
        args: &IsAuthorizedInvokeArgs,
    ) -> Result<IsAuthorizedResult, PVMError> {
        tracing::info!("Ψ_I (is_authorized) invoked.");

        // retrieve the service account code via historical lookup
        let Some(account_code) = state_manager
            .get_account_code_by_lookup(
                args.package.authorizer_service_id,
                args.package.context.lookup_anchor_timeslot,
                &args.package.auth_code_hash,
            )
            .await?
        else {
            // failed to get the `is_authorized` code from the service account
            tracing::warn!("IsAuthorized code not found.");
            return Ok(IsAuthorizedResult::bad());
        };

        if account_code.code().len() > MAX_IS_AUTHORIZED_CODE_SIZE {
            tracing::warn!("IsAuthorized code exceeds maximum allowed.");
            return Ok(IsAuthorizedResult::big());
        }

        let vm_args = IsAuthorizedVmArgs {
            core_index: args.core_index,
        };

        let result = PVMInterface::invoke_with_args(
            state_manager,
            args.package.authorizer_service_id,
            account_code.code(),
            IS_AUTHORIZED_INITIAL_PC,
            IS_AUTHORIZED_GAS_PER_WORK_PACKAGE,
            &vm_args.encode()?,
            &mut InvocationContext::X_I(IsAuthorizedHostContext::new(args.clone())),
        )
        .await?;

        Ok(IsAuthorizedResult::from(result))
    }
}
