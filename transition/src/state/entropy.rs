use crate::error::TransitionError;
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};
use rjam_state::{cache::StateMut, manager::StateManager};
use std::sync::Arc;

/// State transition function of `EpochEntropy`.
///
/// # Transition
///
/// ## On-epoch-change transitions
/// Rotates entropy history, shifting each entry.
pub async fn transition_epoch_entropy_on_epoch_change(
    state_manager: Arc<StateManager>,
    epoch_progressed: bool,
) -> Result<(), TransitionError> {
    state_manager
        .with_mut_epoch_entropy(StateMut::Update, |entropy| {
            if epoch_progressed {
                // Rotate entropy history.
                // [e0, e1, e2, e3] => [e0, e0, e1, e2]; the first e0 will be calculated and inserted below
                entropy.0[3] = entropy.0[2].clone();
                entropy.0[2] = entropy.0[1].clone();
                entropy.0[1] = entropy.0[0].clone();
            }
        })
        .await?;
    Ok(())
}

/// State transition function of `EpochEntropy`.
///
/// # Transition
///
/// ## Per-block transitions
/// Accumulates the VRF output hash of the current block header to the current entropy accumulator.
pub async fn transition_epoch_entropy_per_block(
    state_manager: Arc<StateManager>,
    source_hash: Hash32, // `Y` hash of `H_v`; new incoming entropy hash from the header.
) -> Result<(), TransitionError> {
    state_manager
        .with_mut_epoch_entropy(StateMut::Update, |entropy| {
            let current_accumulator_hash = entropy.current();
            let mut hash_combined = [0u8; 64];
            hash_combined[..32].copy_from_slice(current_accumulator_hash.as_slice());
            hash_combined[32..].copy_from_slice(source_hash.as_slice());
            entropy.0[0] = hash::<Blake2b256>(hash_combined.as_slice()).unwrap();
        })
        .await?;
    Ok(())
}
