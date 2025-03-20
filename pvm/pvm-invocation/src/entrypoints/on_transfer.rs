use rjam_codec::{JamCodecError, JamEncode, JamOutput};
use rjam_common::{Balance, ServiceId};
use rjam_pvm_core::error::{HostCallError::InvalidContext, PVMError};
use rjam_pvm_host::context::{
    partial_state::AccountSandbox, InvocationContext, OnTransferHostContext,
};
use rjam_pvm_interface::invoke::PVMInterface;
use rjam_pvm_types::{
    constants::ON_TRANSFER_INITIAL_PC,
    invoke_args::{DeferredTransfer, OnTransferInvokeArgs},
};
use rjam_state::manager::StateManager;
use std::sync::Arc;

pub struct BalanceChangeSet {
    pub recipient: ServiceId,
    pub added_amount: Balance,
}

/// `Ψ_M` invocation function arguments for `Ψ_T`
#[derive(JamEncode)]
struct OnTransferVMArgs {
    /// Current timeslot index
    timeslot_index: u32,
    /// `s` of `OnTransferInvokeArgs`
    destination: ServiceId,
    /// **`t`** of `OnTransferInvokeArgs`
    transfers: Vec<DeferredTransfer>,
}

#[derive(Default)]
pub struct OnTransferResult {
    pub balance_change_set: Option<BalanceChangeSet>,
    pub recipient_sandbox: Option<AccountSandbox>,
}

impl OnTransferResult {
    fn new(
        recipient: ServiceId,
        added_amount: Balance,
        recipient_sandbox: Option<AccountSandbox>,
    ) -> Self {
        let balance_change_set = if added_amount > 0 {
            Some(BalanceChangeSet {
                recipient,
                added_amount,
            })
        } else {
            None
        };

        Self {
            balance_change_set,
            recipient_sandbox,
        }
    }
}

pub struct OnTransferInvocation;
impl OnTransferInvocation {
    /// OnTransfer invocation function
    ///
    /// # Arguments
    ///
    /// * `state_manager` - A handle to a `StateManager` to access to the global state.
    /// * `args` - On-Transfer entry-point function arguments.
    ///
    /// Represents `Ψ_T` of the GP
    pub async fn on_transfer(
        state_manager: Arc<StateManager>,
        args: &OnTransferInvokeArgs,
    ) -> Result<OnTransferResult, PVMError> {
        if args.transfers.is_empty() {
            return Ok(OnTransferResult::default());
        }

        let total_amount = args.transfers.iter().map(|t| t.amount).sum();
        let total_gas_limit = args.transfers.iter().map(|t| t.gas_limit).sum();

        let Some(code) = state_manager.get_account_code(args.destination).await? else {
            return Ok(OnTransferResult::default());
        };

        let curr_timeslot = state_manager.get_timeslot().await?;

        let vm_args = OnTransferVMArgs {
            timeslot_index: curr_timeslot.slot(),
            destination: args.destination,
            transfers: args.transfers.clone(),
        };

        let ctx = OnTransferHostContext::new(state_manager.clone(), args.destination).await?;
        let mut on_transfer_ctx = InvocationContext::X_T(ctx);

        let _ = PVMInterface::invoke_with_args(
            state_manager.clone(),
            args.destination,
            &code,
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &vm_args.encode()?,
            &mut on_transfer_ctx,
        )
        .await?;

        let OnTransferHostContext {
            mut accounts_sandbox,
        } = if let InvocationContext::X_T(x) = on_transfer_ctx {
            x
        } else {
            return Err(PVMError::HostCallError(InvalidContext));
        };

        let recipient_sandbox = accounts_sandbox
            .get_account_sandbox(state_manager, args.destination)
            .await?
            .cloned();

        Ok(OnTransferResult::new(
            args.destination,
            total_amount,
            recipient_sandbox,
        ))
    }
}
