use crate::{state::safrole::compute_next_slot_sealers, state_prediction::epoch_progressed};
use fr_common::TimeslotIndex;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{ActiveSet, SlotSealer, SlotSealerError, Timeslot},
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SlotSealerPredictionError {
    #[error("State access failed: {0}")]
    State(#[from] StateManagerError),
    #[error("Failed to derive slot sealers: {0}")]
    Slot(#[from] SlotSealerError),
}

/// Predicts post slot sealers state (γ_S′) before actually running STFs.
pub async fn predict_post_slot_sealer(
    state_manager: Arc<StateManager>,
    header_timeslot_index: TimeslotIndex,
) -> Result<SlotSealer, SlotSealerPredictionError> {
    let prior_timeslot = state_manager.get_timeslot_clean().await?;
    let new_timeslot = Timeslot::new(header_timeslot_index);
    let mut safrole_clean = state_manager.get_safrole_clean().await?;
    let entropy_clean = state_manager.get_epoch_entropy_clean().await?;
    if epoch_progressed(&prior_timeslot, &new_timeslot) {
        // Simulate slot sealers transition
        let post_active_set = ActiveSet(safrole_clean.pending_set.clone());
        let post_entropy_2 = entropy_clean.first_history();
        let predicted_slot_sealer = compute_next_slot_sealers(
            &safrole_clean,
            &prior_timeslot,
            &new_timeslot,
            &post_active_set,
            post_entropy_2,
        )?;
        safrole_clean.slot_sealers = predicted_slot_sealer;
        Ok(safrole_clean.slot_sealers.get_slot_sealer(&new_timeslot))
    } else {
        Ok(safrole_clean.slot_sealers.get_slot_sealer(&new_timeslot))
    }
}
