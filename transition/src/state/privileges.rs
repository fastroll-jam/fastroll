use crate::error::TransitionError;
use fr_pvm_invocation::prelude::AccumulatePartialState;
use fr_state::{cache::StateMut, error::StateManagerError, manager::StateManager};
use std::sync::Arc;

pub(crate) async fn run_privileged_transitions(
    state_manager: Arc<StateManager>,
    partial_state_union: AccumulatePartialState<StateManager>,
) -> Result<(), TransitionError> {
    // Transition staging set
    if let Some(new_staging_set) = partial_state_union.new_staging_set {
        state_manager
            .with_mut_staging_set(
                StateMut::Update,
                |staging_set| -> Result<(), StateManagerError> {
                    *staging_set = new_staging_set;
                    Ok(())
                },
            )
            .await?;
    }

    // Transition auth queue
    let auth_queue_sandboxed = partial_state_union.auth_queue;
    state_manager
        .with_mut_auth_queue(
            StateMut::Update,
            |auth_queue| -> Result<(), StateManagerError> {
                *auth_queue = auth_queue_sandboxed;
                Ok(())
            },
        )
        .await?;

    // Transition privileged services
    let manager_service_sandboxed = partial_state_union.manager_service;
    let assign_services_sandboxed = partial_state_union.assign_services.last_confirmed;
    let designate_service_sandboxed = partial_state_union.designate_service.last_confirmed;
    let registrar_service_sandboxed = partial_state_union.registrar_service.last_confirmed;
    let always_accumulate_services_sandboxed = partial_state_union.always_accumulate_services;
    state_manager
        .with_mut_privileged_services(
            StateMut::Update,
            |privileges| -> Result<(), StateManagerError> {
                privileges.manager_service = manager_service_sandboxed;
                privileges.assign_services = assign_services_sandboxed;
                privileges.designate_service = designate_service_sandboxed;
                privileges.registrar_service = registrar_service_sandboxed;
                privileges.always_accumulate_services = always_accumulate_services_sandboxed;
                Ok(())
            },
        )
        .await?;

    Ok(())
}
