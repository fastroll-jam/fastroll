use crate::error::TransitionError;
use rjam_common::Address;
use rjam_pvm_invocation::{
    accumulation::{
        invoke::{accumulate_outer, OuterAccumulationResult},
        utils::select_deferred_transfers,
    },
    PVMInvocation, ACCUMULATION_GAS_ALL_CORES,
};
use rjam_state::StateManager;
use rjam_types::common::{transfers::DeferredTransfer, workloads::WorkReport};
use std::collections::HashSet;

/// State transition function for Accumulate context state components.
///
/// The `accumulate` PVM entrypoint invokes host functions that directly modify state cache entries
/// via the `StateManager`:
/// - `Service Accounts`:
///     - host_write
///     - host_new
///     - host_upgrade
///     - host_transfer
///     - host_solicit
///     - host_forget
/// - `PrivilegedServices`:
///     - host_bless
/// - `StagingSet`:
///     - host_designate
/// - `AuthQueue`:
///     - host_assign
pub fn transition_accumulate_contexts(
    state_manager: &StateManager,
    reports: &[WorkReport],
) -> Result<OuterAccumulationResult, TransitionError> {
    let always_accumulate_services = &state_manager
        .get_privileged_services()?
        .always_accumulate_services;

    Ok(accumulate_outer(
        state_manager,
        ACCUMULATION_GAS_ALL_CORES,
        reports,
        always_accumulate_services,
    )?)
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
pub fn transition_on_transfer(
    state_manager: &StateManager,
    transfers: &[DeferredTransfer],
) -> Result<(), TransitionError> {
    // Gather all unique destination addresses.
    let destinations: HashSet<Address> = transfers.iter().map(|t| t.to).collect();

    // Invoke PVM `on-transfer` entrypoint for each destination.
    for destination in destinations {
        let selected_transfers = select_deferred_transfers(transfers, destination);
        PVMInvocation::on_transfer(state_manager, destination, selected_transfers)?;
    }

    Ok(())
}
