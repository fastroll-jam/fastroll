use crate::TransitionError;
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::state::timeslot::Timeslot;

/// State transition function of `Timeslot`.
///
/// # Transitions
///
/// ## Per-block transitions
/// * `tau`: Sets the most recent timeslot value to the header timeslot index.
pub fn transition_timeslot(
    state_manager: &StateManager,
    header_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let prior_timeslot = state_manager.get_timeslot()?; // Timeslot of the parent block.
    validate_timeslot(&prior_timeslot, header_timeslot)?;

    state_manager.with_mut_timeslot(StateWriteOp::Update, |timeslot| {
        *timeslot = header_timeslot.clone();
    })?;
    Ok(())
}

fn validate_timeslot(
    prior_timeslot: &Timeslot,
    current_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
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
