use fr_common::{EpochIndex, TimeslotIndex};
use fr_crypto::{types::Ed25519PubKey, vrf::bandersnatch_vrf::RingVrfVerifier};
use fr_state::{
    manager::StateManager,
    types::{StagingSet, ValidatorSet},
};
use std::sync::Arc;

/// Spawns dedicated blocking thread(s) to construct a RingVrfVerifier and the corresponding Ring Root.
/// Once created, stores them in the ring cache of the `StateManager`.
pub fn schedule_ring_cache_update(
    state_manager: Arc<StateManager>,
    next_epoch_index: EpochIndex,
    curr_timeslot_index: TimeslotIndex,
    mut new_staging_set: StagingSet,
    curr_punish_set: Vec<Ed25519PubKey>,
) {
    tokio::task::spawn_blocking(move || {
        new_staging_set.nullify_punished_validators(&curr_punish_set);
        match RingVrfVerifier::new(&new_staging_set) {
            Ok(verifier) => {
                let ring_root = match verifier.compute_ring_root() {
                    Ok(ring_root) => ring_root,
                    Err(e) => {
                        tracing::error!(
                            "Failed to compute ring root on privileged transitions: {e:?}"
                        );
                        return;
                    }
                };
                // Cache ring verifier and ring root for the next epoch
                state_manager.update_ring_cache(
                    next_epoch_index,
                    curr_timeslot_index,
                    verifier,
                    ring_root,
                );
                tracing::info!(
                    "A new RingVrfVerifier constructed and cached on privileged transitions"
                );
            }
            Err(e) => {
                tracing::error!(
                    "Failed to construct a new RingVrfVerifier on privileged transitions: {e:?}"
                );
            }
        }
    });
}
