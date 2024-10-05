use crate::TransitionError;
use rjam_state::StateManager;
use rjam_types::extrinsics::tickets::TicketExtrinsicEntry;

/// State transition function of `SafroleState`.
pub fn transition_safrole(
    state_manager: &StateManager,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    Ok(())
}
