use fr_codec::prelude::*;
use fr_common::{Hash32, ServiceId, UnsignedGas, HASH_SIZE, MAX_SERVICE_CODE_SIZE};
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
};
use fr_state::manager::StateManager;
use std::sync::Arc;

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
    pub yielded_accumulate_hash: Option<Hash32>,
    /// `u`: Amount of gas used by a single-service accumulation
    pub gas_used: UnsignedGas,
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
        partial_state: &AccumulatePartialState,
        args: &AccumulateInvokeArgs,
    ) -> Result<AccumulateResult, PVMError> {
        tracing::info!("Ψ_A (accumulate) invoked.");

        let Some(account_code) = state_manager.get_account_code(args.accumulate_host).await? else {
            tracing::warn!("Accumulate service code not found.");
            return Ok(AccumulateResult::default());
        };

        if account_code.code().len() > MAX_SERVICE_CODE_SIZE {
            tracing::warn!("Accumulate service code exceeds maximum allowed.");
            return Ok(AccumulateResult::default());
        }

        let epoch_entropy = state_manager.get_epoch_entropy().await?;
        let curr_entropy = epoch_entropy.current(); // TODO: ensure this value is post entropy accumulation (`η0′`).
        let curr_timeslot = state_manager.get_timeslot().await?;

        let vm_args = AccumulateVMArgs {
            timeslot_index: curr_timeslot.slot(),
            accumulate_host: args.accumulate_host,
            operands_count: args.operands.len(),
        };

        let ctx = AccumulateHostContext::new(
            state_manager.clone(),
            partial_state.clone(),
            args.accumulate_host,
            curr_entropy.clone(),
            &curr_timeslot,
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

        let AccumulateHostContextPair { x, y } =
            if let InvocationContext::X_A(pair) = accumulate_ctx {
                pair
            } else {
                return Err(PVMError::HostCallError(InvalidContext));
            };

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
                    gas_used: x.gas_used,
                    accumulate_host: x.accumulate_host,
                })
            }
            PVMInvocationOutput::OutputUnavailable => Ok(AccumulateResult {
                partial_state: x.partial_state,
                deferred_transfers: x.deferred_transfers,
                yielded_accumulate_hash: x.yielded_accumulate_hash,
                gas_used: x.gas_used,
                accumulate_host: x.accumulate_host,
            }),
            PVMInvocationOutput::OutOfGas(_) | PVMInvocationOutput::Panic(_) => {
                Ok(AccumulateResult {
                    partial_state: y.partial_state,
                    deferred_transfers: y.deferred_transfers,
                    yielded_accumulate_hash: y.yielded_accumulate_hash,
                    gas_used: x.gas_used, // Note: taking gas usage from the `x` context
                    accumulate_host: x.accumulate_host,
                })
            }
        }
    }
}
