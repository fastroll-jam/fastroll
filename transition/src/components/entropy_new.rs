use crate::TransitionError;
use rjam_common::Hash32;
use rjam_crypto::utils::blake2b_256;
use rjam_state::{StateManager, StateWriteOp};

/// State transition function of `EntropyAccumulator`.
pub fn transition_entropy_accumulator(
    state_manager: &StateManager,
    source_hash: Hash32, // `Y` hash of `H_v`; new incoming entropy hash from the header.
) -> Result<(), TransitionError> {
    let current_timeslot = &state_manager.get_timeslot()?; // TODO: ensure the timeslot transition is already completed

    state_manager.with_mut_entropy_accumulator(StateWriteOp::Update, |acc| {
        if current_timeslot.is_new_epoch() {
            // Rotate entropy histories if current timeslot is the first block of a new epoch.
            // [e0, e1, e2, e3] => [e0, e0, e1, e2]; the first e0 will be calculated and inserted below
            acc.0.copy_within(0..3, 1);
        }

        // per-block operations
        let current_accumulator_hash = acc.current();
        let mut hash_combined = [0u8; 64];
        hash_combined[..32].copy_from_slice(current_accumulator_hash.as_slice());
        hash_combined[32..].copy_from_slice(source_hash.as_slice());
        acc.0[0] = blake2b_256(hash_combined.as_slice()).unwrap();
    })?;

    Ok(())
}
