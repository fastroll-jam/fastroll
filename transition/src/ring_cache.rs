use crate::error::TransitionError;
use fr_codec::prelude::*;
use fr_common::{Hash32, TimeslotIndex};
use fr_crypto::{hash, types::Ed25519PubKey, vrf::bandersnatch_vrf::RingVrfVerifier, Blake2b256};
use fr_state::{
    manager::{RingContext, StateManager},
    types::{StagingSet, ValidatorSet},
};
use std::sync::Arc;

/// Computes the hash for a staging set after applying the current punish set.
pub fn compute_effective_staging_set_hash(
    staging_set: &StagingSet,
    punish_set: &[Ed25519PubKey],
) -> Result<Hash32, TransitionError> {
    let mut effective_set = staging_set.clone();
    effective_set.nullify_punished_validators(punish_set);
    Ok(hash::<Blake2b256>(&effective_set.encode()?)?)
}

/// Spawns dedicated blocking thread(s) to construct a RingVrfVerifier and the corresponding Ring Root.
/// Once created, stores them in the ring cache of the `StateManager`.
pub fn schedule_ring_cache_update(
    state_manager: Arc<StateManager>,
    curr_timeslot_index: TimeslotIndex,
    mut new_staging_set: StagingSet,
    curr_punish_set: Vec<Ed25519PubKey>,
    expected_staging_set_hash: Hash32,
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

                let ring_context = RingContext {
                    inserted_at: curr_timeslot_index,
                    validator_set: (*new_staging_set).clone(),
                    verifier,
                    ring_root,
                };

                // Cache ring verifier and ring root for the next epoch.
                // This update is guarded so if the new ring context becomes stale at this point
                // (due to forking, etc.) it will be discarded.
                state_manager.update_staging_ring_cache_entry_guarded(
                    ring_context,
                    expected_staging_set_hash,
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
