use fr_codec::prelude::*;
use fr_common::{Octets, ServiceId, UnsignedGas, HASH_SIZE, MAX_SERVICE_CODE_SIZE};
use fr_crypto::octets_to_hash32;
use fr_pvm_host::{
    context::{
        partial_state::AccumulatePartialState, AccumulateHostContext, AccumulateHostContextPair,
        InvocationContext,
    },
    error::HostCallError::InvalidContext,
};
use fr_pvm_interface::{
    error::PVMError,
    invoke::{PVMInterface, PVMInvocationOutput},
};
use fr_pvm_types::{
    constants::ACCUMULATE_INITIAL_PC,
    invoke_args::{AccumulateInvokeArgs, DeferredTransfer},
    invoke_results::AccumulationOutputHash,
};
use fr_state::manager::StateManager;
use std::{collections::HashSet, sync::Arc};

/// `Ψ_M` invocation function arguments for `Ψ_A`
#[derive(JamEncode)]
struct AccumulateVMArgs {
    /// Current timeslot index
    timeslot_index: u32,
    /// `s` of `AccumulateInvokeArgs`
    accumulate_host: ServiceId,
    /// Length of **`o`** of `AccumulateInvokeArgs`
    operands_count: usize,
}

#[derive(Default)]
pub struct AccumulateResult {
    /// **`o`**: The posterior partial state
    pub partial_state: AccumulatePartialState,
    /// **`t`**: All transfers deferred by a single-service accumulation
    pub deferred_transfers: Vec<DeferredTransfer>,
    /// `b`: Accumulation result hash
    pub yielded_accumulate_hash: Option<AccumulationOutputHash>,
    /// `u`: Amount of gas used by a single-service accumulation
    pub gas_used: UnsignedGas,
    /// **`p`**: Provided preimage entries during accumulation
    pub provided_preimages: HashSet<(ServiceId, Octets)>,
    pub accumulate_host: ServiceId,
}

pub struct AccumulateInvocation;
impl AccumulateInvocation {
    /// Accumulate invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - A handle to a `StateManager` to access to the global state.
    /// * `partial_state` - Partial state copied from the state manager that is free to be read and updated during the accumulation.
    /// * `args` - Accumulate entry-point function arguments.
    ///
    /// Represents `Ψ_A` of the GP
    pub(crate) async fn accumulate(
        state_manager: Arc<StateManager>,
        partial_state: AccumulatePartialState,
        args: &AccumulateInvokeArgs,
    ) -> Result<AccumulateResult, PVMError> {
        tracing::info!("Ψ_A (accumulate) invoked.");

        let Some(account_code) = state_manager.get_account_code(args.accumulate_host).await? else {
            tracing::warn!("Accumulate service code not found.");
            return Ok(AccumulateResult {
                accumulate_host: args.accumulate_host,
                partial_state,
                ..Default::default()
            });
        };

        let code_len = account_code.code().len();
        if code_len > MAX_SERVICE_CODE_SIZE {
            tracing::warn!("Accumulate service code exceeds maximum allowed.");
            return Ok(AccumulateResult {
                accumulate_host: args.accumulate_host,
                partial_state,
                ..Default::default()
            });
        }
        tracing::debug!("Account code length: {code_len} octets");

        let epoch_entropy = state_manager.get_epoch_entropy().await?;
        let curr_entropy = epoch_entropy.current(); // TODO: ensure this value is post entropy accumulation (`η0′`).

        let vm_args = AccumulateVMArgs {
            timeslot_index: args.curr_timeslot_index,
            accumulate_host: args.accumulate_host,
            operands_count: args.operands.len(),
        };

        let ctx = AccumulateHostContext::new(
            state_manager.clone(),
            partial_state,
            args.accumulate_host,
            curr_entropy.clone(),
            args.curr_timeslot_index,
            args.clone(),
        )
        .await?;
        let ctx_pair = AccumulateHostContextPair {
            x: Box::new(ctx.clone()),
            y: Box::new(ctx),
        };
        let mut accumulate_ctx = InvocationContext::X_A(ctx_pair);

        let result = PVMInterface::invoke_with_args(
            state_manager,
            args.accumulate_host,
            account_code.code(),
            ACCUMULATE_INITIAL_PC,
            args.gas_limit,
            &vm_args.encode()?,
            &mut accumulate_ctx,
        )
        .await?;

        let InvocationContext::X_A(pair) = accumulate_ctx else {
            return Err(PVMError::HostCallError(InvalidContext));
        };
        let AccumulateHostContextPair { x, y } = pair;

        match result.output {
            PVMInvocationOutput::Output(output) => {
                let accumulate_result_hash = if output.len() == HASH_SIZE {
                    octets_to_hash32(&output)
                } else {
                    x.yielded_accumulate_hash
                };

                Ok(AccumulateResult {
                    partial_state: x.partial_state,
                    deferred_transfers: x.deferred_transfers,
                    yielded_accumulate_hash: accumulate_result_hash,
                    gas_used: result.gas_used,
                    accumulate_host: x.accumulate_host,
                    provided_preimages: x.provided_preimages,
                })
            }
            PVMInvocationOutput::OutputUnavailable => Ok(AccumulateResult {
                partial_state: x.partial_state,
                deferred_transfers: x.deferred_transfers,
                yielded_accumulate_hash: x.yielded_accumulate_hash,
                gas_used: result.gas_used,
                accumulate_host: x.accumulate_host,
                provided_preimages: x.provided_preimages,
            }),
            PVMInvocationOutput::OutOfGas(_) | PVMInvocationOutput::Panic(_) => {
                Ok(AccumulateResult {
                    partial_state: y.partial_state,
                    deferred_transfers: y.deferred_transfers,
                    yielded_accumulate_hash: y.yielded_accumulate_hash,
                    gas_used: result.gas_used, // Note: taking gas usage from the `x` context
                    accumulate_host: x.accumulate_host,
                    provided_preimages: y.provided_preimages,
                })
            }
        }
    }
}
