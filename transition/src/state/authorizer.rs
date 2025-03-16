use crate::error::TransitionError;
use rjam_common::{CoreIndex, AUTH_QUEUE_SIZE, MAX_AUTH_POOL_SIZE};
use rjam_state::{StateManager, StateMut};
use rjam_types::{extrinsics::guarantees::GuaranteesXt, state::timeslot::Timeslot};
use std::sync::Arc;

/// State transition function of `AuthPool`.
///
/// # Transitions
///
/// On every block, the pool for each core must be updated based on the guarantees extrinsics submitted.
/// If a guarantees extrinsic entry exists for a given core and thus used the computing resource (core-time),
/// the oldest authorizer hash in the pool is removed, and the next authorizer hash in the queue
/// is added to the pool. If no guarantee exists, the next authorizer hash is still
/// added to the pool, discarding the oldest entry from the pool if it is full.
pub async fn transition_auth_pool(
    state_manager: Arc<StateManager>,
    guarantees_xt: &GuaranteesXt,
    header_timeslot: Timeslot,
) -> Result<(), TransitionError> {
    // Get the current auth queue state, after its mutation via the accumulation process.
    let auth_queue = state_manager.get_auth_queue().await?;

    state_manager
        .with_mut_auth_pool(StateMut::Update, |pool| {
            for (core, core_pool) in pool.0.iter_mut().enumerate() {
                // Find a guarantees extrinsics entry that utilized the current core, if there is any.
                let report_used_core = guarantees_xt
                    .iter()
                    .find(|guarantee| guarantee.work_report.core_index() == core as CoreIndex)
                    .map(|guarantee| guarantee.work_report.authorizer_hash());

                // Remove the oldest authorizer hash from the pool that matches the used one for the
                // current core in this block.
                if let Some(auth_hash) = report_used_core {
                    if let Some(index) = core_pool.iter().position(|&hash| hash == auth_hash) {
                        core_pool.remove(index);
                    }
                }

                // Appends an authorizer hash entry from the queue to the pool.
                let effective_current_timeslot_index =
                    header_timeslot.slot() as usize % AUTH_QUEUE_SIZE;
                let queue_entry = auth_queue.0[core][effective_current_timeslot_index];

                if core_pool.len() == MAX_AUTH_POOL_SIZE {
                    core_pool.remove(0);
                }
                core_pool.push(queue_entry);
            }
        })
        .await?;

    Ok(())
}
