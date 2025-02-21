use crate::error::TransitionError;
use rjam_common::ServiceId;
use rjam_pvm_core::types::invoke_args::OnTransferInvokeArgs;
use rjam_pvm_invocation::{accumulation::utils::select_deferred_transfers, PVMInvocation};
use rjam_state::StateManager;
use rjam_types::common::transfers::DeferredTransfer;
use std::collections::HashSet;
// FIXME
// /// State transition function for Accumulate context state components.
// ///
// /// The `accumulate` PVM entrypoint invokes host functions that directly modify state cache entries
// /// via the `StateManager`:
// /// - `Service Accounts`:
// ///     - host_write
// ///     - host_new
// ///     - host_upgrade
// ///     - host_transfer
// ///     - host_solicit
// ///     - host_forget
// /// - `PrivilegedServices`:
// ///     - host_bless
// /// - `StagingSet`:
// ///     - host_designate
// /// - `AuthQueue`:
// ///     - host_assign
// pub async fn transition_accumulate_contexts(
//     state_manager: &StateManager,
//     reports: Vec<WorkReport>,
// ) -> Result<OuterAccumulationResult, TransitionError> {
//     let always_accumulate_services = &state_manager
//         .get_privileged_services()
//         .await?
//         .always_accumulate_services;
//
//     Ok(accumulate_outer(
//         state_manager,
//         ACCUMULATION_GAS_ALL_CORES,
//         reports,
//         always_accumulate_services,
//     )?)
// }

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
