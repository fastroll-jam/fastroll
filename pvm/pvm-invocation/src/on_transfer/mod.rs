use crate::error::PVMInvokeError;
use fr_codec::prelude::*;
use fr_common::{Balance, ServiceId, TimeslotIndex, UnsignedGas, MAX_SERVICE_CODE_SIZE};
use fr_pvm_host::{
    context::{partial_state::AccountSandbox, InvocationContext, OnTransferHostContext},
    error::HostCallError::InvalidContext,
};
use fr_pvm_interface::invoke::PVMInterface;
use fr_pvm_types::{constants::ON_TRANSFER_INITIAL_PC, invoke_args::OnTransferInvokeArgs};
use fr_state::{manager::StateManager, provider::HostStateProvider};
use std::sync::Arc;

pub struct BalanceChangeSet {
    pub recipient: ServiceId,
    pub added_amount: Balance,
}

/// `Ψ_M` invocation function arguments for `Ψ_T`
#[derive(JamEncode)]
struct OnTransferVMArgs {
    /// Current timeslot index
    timeslot_index: TimeslotIndex,
    /// `s` of `OnTransferInvokeArgs`
    destination: ServiceId,
    /// Length of **`t`** of `OnTransferInvokeArgs`
    transfers_count: usize,
}

pub struct OnTransferResult<S: HostStateProvider> {
    pub gas_used: UnsignedGas,
    pub balance_change_set: Option<BalanceChangeSet>,
    pub recipient_sandbox: Option<AccountSandbox<S>>,
}

impl<S: HostStateProvider> Default for OnTransferResult<S> {
    fn default() -> Self {
        Self {
            gas_used: 0,
            balance_change_set: None,
            recipient_sandbox: None,
        }
    }
}

impl<S: HostStateProvider> OnTransferResult<S> {
    fn new(
        recipient: ServiceId,
        added_amount: Balance,
        recipient_sandbox: Option<AccountSandbox<S>>,
        gas_used: UnsignedGas,
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
            gas_used,
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
    ) -> Result<OnTransferResult<StateManager>, PVMInvokeError> {
        tracing::info!("Ψ_T (on_transfer) invoked.");

        if args.transfers.is_empty() {
            return Ok(OnTransferResult::default());
        }

        let total_amount = args.transfers.iter().map(|t| t.amount).sum();
        let total_gas_limit = args.transfers.iter().map(|t| t.gas_limit).sum();

        let curr_timeslot = state_manager.get_timeslot().await?;

        let vm_args = OnTransferVMArgs {
            timeslot_index: curr_timeslot.slot(),
            destination: args.destination,
            transfers_count: args.transfers.len(),
        };

        let epoch_entropy = state_manager.get_epoch_entropy().await?;
        let curr_entropy = epoch_entropy.current();
        let mut ctx = OnTransferHostContext::new(
            state_manager.clone(),
            args.destination,
            curr_entropy.clone(),
            args.clone(),
        )
        .await?;
        let mut on_transfer_ctx = InvocationContext::X_T(ctx.clone());

        let recipient_sandbox_unchanged = ctx
            .accounts_sandbox
            .get_account_sandbox(state_manager.clone(), args.destination)
            .await?
            .cloned();

        let Some(account_code) = state_manager.get_account_code(args.destination).await? else {
            tracing::warn!("OnTransfer service code not found.");
            return Ok(OnTransferResult::new(
                args.destination,
                total_amount,
                recipient_sandbox_unchanged,
                0,
            ));
        };

        if account_code.code().len() > MAX_SERVICE_CODE_SIZE {
            tracing::warn!("OnTransfer service code exceeds maximum allowed.");
            return Ok(OnTransferResult::new(
                args.destination,
                total_amount,
                recipient_sandbox_unchanged,
                0,
            ));
        }

        let result = PVMInterface::invoke_with_args(
            state_manager.clone(),
            args.destination,
            account_code.code(),
            ON_TRANSFER_INITIAL_PC,
            total_gas_limit,
            &vm_args.encode()?,
            &mut on_transfer_ctx,
            Some(vm_args.timeslot_index),
        )
        .await?;

        let InvocationContext::X_T(mut post_x) = on_transfer_ctx else {
            return Err(PVMInvokeError::HostCallError(InvalidContext));
        };

        let recipient_sandbox = post_x
            .accounts_sandbox
            .get_account_sandbox(state_manager, args.destination)
            .await?
            .cloned();

        Ok(OnTransferResult::new(
            args.destination,
            total_amount,
            recipient_sandbox,
            result.gas_used,
        ))
    }
}
