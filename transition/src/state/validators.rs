use crate::error::TransitionError;
use fr_state::{cache::StateMut, error::StateManagerError, manager::StateManager};
use std::sync::Arc;

/// State transition function of `ActiveSet`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `κ`: Sets the active set to the prior pending set.
pub async fn transition_active_set(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        let prior_pending_set = state_manager.get_safrole_clean().await?.pending_set;
        state_manager
            .with_mut_active_set(
                StateMut::Update,
                |active_set| -> Result<(), StateManagerError> {
                    active_set.0 = prior_pending_set;
                    Ok(())
                },
            )
            .await?;
    }
    Ok(())
}

/// State transition function of `PastSet`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `λ`: Sets the past set to the prior active set.
pub async fn transition_past_set(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        let prior_active_set = state_manager.get_active_set_clean().await?;
        state_manager
            .with_mut_past_set(
                StateMut::Update,
                |past_set| -> Result<(), StateManagerError> {
                    past_set.0 = prior_active_set.0;
                    Ok(())
                },
            )
            .await?;
    }
    Ok(())
}
