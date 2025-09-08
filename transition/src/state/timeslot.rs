use crate::error::TransitionError;
use fr_state::{cache::StateMut, error::StateManagerError, manager::StateManager, types::Timeslot};
use std::sync::Arc;

/// State transition function of `Timeslot`.
///
/// # Transitions
///
/// ## Per-block transitions
/// * `τ`: Sets the most recent timeslot value to the header timeslot index.
pub async fn transition_timeslot(
    state_manager: Arc<StateManager>,
    header_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    #[cfg(not(feature = "fuzz"))]
    {
        let prior_timeslot = state_manager.get_timeslot().await?; // Timeslot of the parent block.
        validate_timeslot(&prior_timeslot, header_timeslot)?;
    }

    state_manager
        .with_mut_timeslot(
            StateMut::Update,
            |timeslot| -> Result<(), StateManagerError> {
                *timeslot = *header_timeslot;
                Ok(())
            },
        )
        .await?;
    Ok(())
}

#[cfg(not(feature = "fuzz"))]
fn validate_timeslot(
    prior_timeslot: &Timeslot,
    current_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    // Skip genesis block validation
    let genesis_timeslot = Timeslot::new(0);
    if prior_timeslot == &genesis_timeslot && current_timeslot == &genesis_timeslot {
        return Ok(());
    }

    // Timeslot value must be greater than the parent block
    if current_timeslot <= prior_timeslot {
        return Err(TransitionError::InvalidTimeslot {
            next_slot: current_timeslot.slot(),
            current_slot: prior_timeslot.slot(),
        });
    }

    // Timeslot value cannot be in the future
    if current_timeslot.is_in_future() {
        return Err(TransitionError::FutureTimeslot(current_timeslot.slot()));
    }

    Ok(())
}
