use crate::error::TransitionError;
use rjam_common::WorkReport;
use rjam_pvm_invocation::{
    accumulation::invoke::{accumulate_outer, OuterAccumulationResult},
    ACCUMULATION_GAS_ALL_CORES,
};
use rjam_state::StateManager;

/// State transition function for Accumulate context state components.
///
/// This function manages state transitions for the following components:
/// - `ServiceAccount` (post-preimage integration)
/// - `PrivilegedServices`
/// - `AuthQueue`
/// - `StagingSet`
///
/// The `accumulate` entrypoint invokes host functions that directly modify `StateCache` entries
/// via the `StateManager`:
/// - `ServiceAccount`:
///     - host_write
///     - host_new
///     - host_upgrade
///     - host_transfer
///     - host_solicit
///     - host_forget
/// - `PrivilegedServices`:
///     - host_empower
/// - `StagingSet`:
///     - host_designate
/// - `AuthQueue`:
///     - host_assign
///
/// The PVM `accumulate` entrypoint is called to execute the Accumulate code and update the relevant state.
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
