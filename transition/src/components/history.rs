use crate::error::TransitionError;
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_merkle::mmr::MerkleMountainRange;
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::state::history::BlockHistoryEntry;

/// State transition function of `BlockHistory`, updating the parent block's state root.
///
/// # Transitions
///
/// This handles the first state transition for `BlockHistory`, yielding `β†`.
/// When a new block history entry is appended to the sequence, the block's state root field is
/// initially set to an empty hash, as each block stores the state root of its parent block.
/// This function performs the necessary update to reflect the correct parent state root
/// before accumulation occurs for the current block.
pub fn transition_block_history_parent_root(
    state_manager: &StateManager,
    root: Hash32,
) -> Result<(), TransitionError> {
    let history = state_manager.get_block_history()?;
    if history.0.is_empty() {
        return Ok(());
    }

    state_manager.with_mut_block_history(StateWriteOp::Update, |history| {
        let last_index = history.0.len() - 1;
        history.0[last_index].set_state_root(root);
    })?;

    Ok(())
}

/// State transition function of `BlockHistory`, appending a new block history entry to the vector.
///
/// # Transitions
///
/// This handles the second state transition for `BlockHistory`, yielding `β′`.
/// It constructs a new block history entry using the provided block header, work package hashes
/// from guarantee extrinsics, and the accumulation result history Merkle Mountain Range (MMR).
/// The new entry is then appended to the `BlockHistory` vector. If the total number of entries
/// exceeds the maximum allowed (`H = 8`), the oldest entry is removed to maintain the length limit,
/// ensuring only the most recent block history are retained.
pub fn transition_block_history_append(
    state_manager: &StateManager,
    header_hash: Hash32,
    accumulate_root: Hash32,
    work_package_hashes: &[Hash32],
) -> Result<(), TransitionError> {
    let block_history = state_manager.get_block_history()?;
    let mut mmr = match block_history.get_latest_history().cloned() {
        Some(history) => history.accumulation_result_mmr,
        None => MerkleMountainRange::new(),
    };
    mmr.append(accumulate_root)?;

    state_manager.with_mut_block_history(StateWriteOp::Update, |history| {
        history.append(BlockHistoryEntry {
            header_hash,
            accumulation_result_mmr: mmr,
            state_root: HASH32_EMPTY,
            work_package_hashes: work_package_hashes.to_vec(),
        });
    })?;

    Ok(())
}
