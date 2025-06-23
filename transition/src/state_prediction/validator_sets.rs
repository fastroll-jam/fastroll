use crate::state_prediction::epoch_progressed;
use fr_common::TimeslotIndex;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{ActiveSet, PastSet, Timeslot},
};
use std::sync::Arc;

pub async fn predict_active_set(
    state_manager: Arc<StateManager>,
    header_timeslot_index: TimeslotIndex,
) -> Result<ActiveSet, StateManagerError> {
    let prior_timeslot = state_manager.get_timeslot_clean().await?;
    let new_timeslot = Timeslot::new(header_timeslot_index);
    if epoch_progressed(&prior_timeslot, &new_timeslot) {
        Ok(ActiveSet(
            state_manager.get_safrole_clean().await?.pending_set,
        ))
    } else {
        state_manager.get_active_set_clean().await
    }
}

pub async fn predict_past_set(
    state_manager: Arc<StateManager>,
    header_timeslot_index: TimeslotIndex,
) -> Result<PastSet, StateManagerError> {
    let prior_timeslot = state_manager.get_timeslot_clean().await?;
    let new_timeslot = Timeslot::new(header_timeslot_index);
    if epoch_progressed(&prior_timeslot, &new_timeslot) {
        Ok(PastSet(state_manager.get_active_set_clean().await?.0))
    } else {
        state_manager.get_past_set_clean().await
    }
}
