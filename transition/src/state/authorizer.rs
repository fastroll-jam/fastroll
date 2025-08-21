use crate::error::TransitionError;
use fr_block::types::extrinsics::guarantees::GuaranteesXt;
use fr_common::{CoreIndex, TimeslotIndex, AUTH_QUEUE_SIZE};
use fr_state::{cache::StateMut, error::StateManagerError, manager::StateManager};
use std::sync::Arc;

/// State transition function of `AuthPool`.
///
/// # Transitions
///
/// On every block, the pool for each core must be updated based on the guarantees extrinsics submitted.
/// If a guarantees extrinsic entry exists for a given core and thus used the computing resource (core-time),
/// such authorizer hash is removed from the pool and an authorizer hash in the queue is added to
/// the pool. If no guarantee exists, the next authorizer hash is still added to the pool,
/// discarding the oldest entry from the pool if it is full.
pub async fn transition_auth_pool(
    state_manager: Arc<StateManager>,
    guarantees_xt: &GuaranteesXt,
    header_timeslot_index: TimeslotIndex,
) -> Result<(), TransitionError> {
    // Get the current auth queue state, after its mutation via the accumulation process.
    let auth_queue = state_manager.get_auth_queue().await?;

    state_manager
        .with_mut_auth_pool(StateMut::Update, |pool| -> Result<(), StateManagerError> {
            for (core_idx, core_pool) in pool.0.iter_mut().enumerate() {
                // If there is any guarantees Xt entry that utilized the current core, take its auth hash.
                let used_auth_hash = guarantees_xt
                    .iter()
                    .find(|guarantee| guarantee.work_report.core_index == core_idx as CoreIndex)
                    .map(|guarantee| &guarantee.work_report.authorizer_hash);

                // Remove the oldest authorizer hash from the pool that matches the used one for the
                // current core in this block.
                if let Some(auth_hash) = used_auth_hash {
                    if let Some(index) = core_pool.iter().position(|hash| hash == auth_hash) {
                        core_pool.remove(index);
                    }
                }

                // Appends an authorizer hash entry from the queue to the pool, removing the oldest
                // entry if the core pool is full.
                let queue_entry_idx = header_timeslot_index as usize % AUTH_QUEUE_SIZE;
                let queue_entry = auth_queue.0[core_idx][queue_entry_idx].clone();
                core_pool.shift_push(queue_entry);
            }
            Ok(())
        })
        .await?;

    Ok(())
}
