use crate::error::TransitionError;
use rjam_common::Hash32;
use rjam_crypto::utils::blake2b_256;
use rjam_state::{StateManager, StateWriteOp};

/// State transition function of `EntropyAccumulator`.
///
/// # Transitions
///
/// ## On-epoch-change transitions
/// * `eta`: Rotates entropy histories, shifting each entry.
///
/// ## Per-block transitions
/// * `eta`: Accumulates the VRF output hash of the current block header to the current entropy state.
pub fn transition_entropy_accumulator(
    state_manager: &StateManager,
    epoch_progressed: bool,
    source_hash: Hash32, // `Y` hash of `H_v`; new incoming entropy hash from the header.
) -> Result<(), TransitionError> {
    state_manager.with_mut_entropy_accumulator(StateWriteOp::Update, |entropy| {
        if epoch_progressed {
            // Rotate entropy histories.
            // [e0, e1, e2, e3] => [e0, e0, e1, e2]; the first e0 will be calculated and inserted below
            entropy.0.copy_within(0..3, 1);
        }

        let current_accumulator_hash = entropy.current();
        let mut hash_combined = [0u8; 64];
        hash_combined[..32].copy_from_slice(current_accumulator_hash.as_slice());
        hash_combined[32..].copy_from_slice(source_hash.as_slice());
        entropy.0[0] = blake2b_256(hash_combined.as_slice()).unwrap();
    })?;

    Ok(())
}
