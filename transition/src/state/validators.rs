use crate::error::TransitionError;
use rjam_state::{StateManager, StateMut};

/// State transition function of `ActiveSet`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `kappa`: Sets the active set to the prior pending set.
///
/// ## Per-block transitions
/// * `kappa`: None.
pub fn transition_active_set(
    state_manager: &StateManager,
    epoch_progressed: bool,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        let prior_pending_set = state_manager.get_safrole()?.pending_set;
        state_manager.with_mut_active_set(StateMut::Update, |active_set| {
            active_set.0 = prior_pending_set;
        })?;
    }
    Ok(())
}

/// State transition function of `PastSet`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `lambda`: Sets the past set to the prior active set.
///
/// ## Per-block transitions
/// * `lambda`: None.
pub fn transition_past_set(
    state_manager: &StateManager,
    epoch_progressed: bool,
) -> Result<(), TransitionError> {
    if epoch_progressed {
        let prior_active_set = state_manager.get_active_set()?;
        state_manager.with_mut_past_set(StateMut::Update, |past_set| {
            past_set.0 = prior_active_set.0;
        })?;
    }
    Ok(())
}
