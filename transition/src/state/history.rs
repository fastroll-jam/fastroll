use crate::error::TransitionError;
use rjam_common::{workloads::work_report::ReportedWorkPackage, Hash32};
use rjam_merkle::mmr::MerkleMountainRange;
use rjam_state::{cache::StateMut, manager::StateManager, types::BlockHistoryEntry};
use std::sync::Arc;

// @GP(7.2::stf::v0.6.5)
/// State transition function of `BlockHistory`, updating the parent block's state root.
///
/// # Transitions
///
/// This handles the first state transition for `BlockHistory`, yielding `β†`.
/// When a new block history entry is appended to the sequence, the block's state root field is
/// initially set to an empty hash, as each block stores the posterior state root of its parent block.
/// This function updates the parent state root once it gets available.
pub async fn transition_block_history_parent_root(
    state_manager: Arc<StateManager>,
    root: Hash32,
) -> Result<(), TransitionError> {
    let history = state_manager.get_block_history_clean().await?;
    if history.0.is_empty() {
        return Ok(());
    }

    state_manager
        .with_mut_block_history(StateMut::Update, |history| {
            let last_index = history.0.len() - 1;
            history.0[last_index].set_state_root(root);
        })
        .await?;

    Ok(())
}

// @GP(7.3::stf::v0.6.5)
// @GP(7.4::stf::v0.6.5)
/// State transition function of `BlockHistory`, appending a new block history entry to the vector.
///
/// # Transitions
///
/// This handles the second state transition for `BlockHistory`, yielding `β′`.
/// It constructs a new block history entry using the provided block header, work package hashes
/// from guarantee extrinsics, and the accumulation result history MMR.
/// The new entry is then appended to the history, with the max length limit of `H`.
/// If the `BlockHistory` becomes full, the oldest entry is removed.
pub async fn transition_block_history_append(
    state_manager: Arc<StateManager>,
    header_hash: Hash32,
    accumulate_root: Hash32,
    reported_packages: Vec<ReportedWorkPackage>,
) -> Result<(), TransitionError> {
    let block_history = state_manager.get_block_history().await?;
    let mut mmr = match block_history.get_latest_history().cloned() {
        Some(history) => history.accumulation_result_mmr,
        None => MerkleMountainRange::new(),
    };
    mmr.append(accumulate_root)?;

    state_manager
        .with_mut_block_history(StateMut::Update, |history| {
            history.append(BlockHistoryEntry {
                header_hash,
                accumulation_result_mmr: mmr,
                state_root: Hash32::default(),
                reported_packages,
            });
        })
        .await?;

    Ok(())
}
