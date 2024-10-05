use crate::{
    components::{
        entropy_new::transition_entropy_accumulator,
        safrole_new::transition_safrole,
        timeslot_new::transition_timeslot,
        validators_new::{transition_active_set, transition_past_set},
    },
    TransitionError,
};
use rjam_crypto::utils::entropy_hash_ietf_vrf;
use rjam_state::StateManager;
use rjam_types::{
    block::header::BlockHeader, extrinsics::tickets::TicketExtrinsicEntry,
    state::timeslot::Timeslot,
};

/// Performs the chain extension procedure by executing a series of state transitions in order.
///
/// 1. Entropy Accumulator: Updates the entropy based on the block header's VRF signature (H_v).
/// 2. Timeslot: Updates the current timeslot based on the block header's timeslot index.
/// 3. Past Set: Updates the set of past validators.
/// 4. Active Set: Updates the set of currently active validators.
/// 5. Safrole: Updates Safrole state components, including ring root calculation and ticket processing.
fn chain_extension_procedure(
    state_manager: &StateManager,
    header: &BlockHeader,
    tickets: &[TicketExtrinsicEntry],
) -> Result<(), TransitionError> {
    // EntropyAccumulator transition
    let header_vrf_signature = header.get_vrf_signature();
    transition_entropy_accumulator(state_manager, entropy_hash_ietf_vrf(header_vrf_signature))?;

    // Timeslot transition
    let header_timeslot_index = header.get_timeslot_index();
    transition_timeslot(state_manager, &Timeslot::new(header_timeslot_index))?;

    // PastSet transition
    transition_past_set(state_manager)?;

    // ActiveSet transition
    transition_active_set(state_manager)?;

    // Safrole transition
    transition_safrole(state_manager, tickets)?;

    Ok(())
}
