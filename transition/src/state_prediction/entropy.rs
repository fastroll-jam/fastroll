use crate::state_prediction::epoch_progressed;
use rjam_common::Hash32;
use rjam_state::{error::StateManagerError, manager::StateManager, types::Timeslot};
use std::sync::Arc;

/// Predicts the third entropy history state (η_3′) before actually running STFs.
pub async fn predict_post_entropy_3(
    state_manager: Arc<StateManager>,
    header_timeslot_index: u32,
) -> Result<Hash32, StateManagerError> {
    let prior_timeslot = state_manager.get_timeslot_clean().await?;
    let new_timeslot = Timeslot::new(header_timeslot_index);
    let entropy_clean = state_manager.get_epoch_entropy_clean().await?;
    if epoch_progressed(&prior_timeslot, &new_timeslot) {
        Ok(entropy_clean.second_history().clone())
    } else {
        Ok(entropy_clean.third_history().clone())
    }
}
