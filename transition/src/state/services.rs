use crate::error::TransitionError;
use rjam_common::{
    ServiceId, UnsignedGas, ACCUMULATION_GAS_ALL_CORES, ACCUMULATION_GAS_PER_CORE, CORE_COUNT,
};
use rjam_pvm_core::types::invoke_args::OnTransferInvokeArgs;
use rjam_pvm_invocation::{
    accumulation::{
        invoke::{accumulate_outer, OuterAccumulationResult},
        utils::select_deferred_transfers,
    },
    PVMInvocation,
};
use rjam_state::StateManager;
use rjam_types::common::{transfers::DeferredTransfer, workloads::WorkReport};
use std::collections::HashSet;

/// Processes state transitions by `accumulate` PVM invocation.
///
/// # Transitions
///
/// The following state components are copied into `AccumulatePartialState` and then mutated
/// during the `accumulate` PVM invocation by host functions. After executing `accumulate`,
/// the mutations in `AccumulatePartialState` are copied back into the `StateManager`.
///
/// ### Service Accounts
/// - `host_write`
/// - `host_new`
/// - `host_upgrade`
/// - `host_transfer`
/// - `host_eject`
/// - `host_solicit`
/// - `host_forget`
/// - `host_yield`
///
/// ### Privileged Services
/// - `host_bless`
///
/// ### Staging Set
/// - `host_designate`
///
/// ### Auth Queue
/// - `host_assign`
pub async fn transition_accumulate_contexts(
    state_manager: &StateManager,
    reports: &[WorkReport],
) -> Result<OuterAccumulationResult, TransitionError> {
    let always_accumulate_services = &state_manager
        .get_privileged_services()
        .await?
        .always_accumulate_services;

    let gas_limit = ACCUMULATION_GAS_ALL_CORES.max(
        ACCUMULATION_GAS_PER_CORE * CORE_COUNT as UnsignedGas
            + always_accumulate_services.values().sum::<UnsignedGas>(),
    );

    accumulate_outer(
        state_manager,
        gas_limit,
        reports,
        always_accumulate_services,
    )
    .await
    .map_err(TransitionError::PVMError)
}

/// Processes deferred transfers for service accounts.
///
/// This function:
/// 1. Identifies unique destination addresses from the input transfers.
/// 2. For each destination, selects relevant transfers and invokes the PVM `on_transfer` entrypoint.
/// 3. Updates service account states based on the PVM invocation results.
///
/// This function implements the second state transition for service accounts,
/// following the `accumulate` PVM invocation.
pub async fn transition_on_transfer(
    state_manager: &StateManager,
    transfers: Vec<DeferredTransfer>,
) -> Result<(), TransitionError> {
    // Gather all unique destination addresses.
    let destinations: HashSet<ServiceId> = transfers.iter().map(|t| t.to).collect();

    // Invoke PVM `on-transfer` entrypoint for each destination.
    for destination in destinations {
        let transfers = select_deferred_transfers(&transfers, destination);
        PVMInvocation::on_transfer(
            state_manager,
            &OnTransferInvokeArgs {
                destination,
                transfers,
            },
        )
        .await?;
    }

    Ok(())
}
