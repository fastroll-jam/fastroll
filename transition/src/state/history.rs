use crate::error::TransitionError;
use fr_common::{
    workloads::work_report::ReportedWorkPackage, AccumulateRoot, BlockHeaderHash, StateRoot,
};
use fr_pvm_types::invoke_results::AccumulationOutputPairs;
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{BlockHistoryEntry, LastAccumulateOutputs},
};
use std::sync::Arc;

/// State transition function of `BlockHistory.history`, updating the parent block's state root.
///
/// # Transitions
///
/// This handles the first state transition for `history` component of `BlockHistory`, yielding `β_H†`.
/// When a new block history entry is appended to the sequence, the block's state root field is
/// initially set to an empty hash, as each block stores the posterior state root of its parent block.
/// This function updates the parent state root once it gets available.
pub async fn transition_block_history_parent_root(
    state_manager: Arc<StateManager>,
    root: StateRoot,
) -> Result<(), TransitionError> {
    let block_history = state_manager.get_block_history_clean().await?;
    if block_history.history.is_empty() {
        return Ok(());
    }

    state_manager
        .with_mut_block_history(
            StateMut::Update,
            |history| -> Result<(), StateManagerError> {
                let last_index = history.history.len() - 1;
                history.history[last_index].set_state_root(root);
                Ok(())
            },
        )
        .await?;

    Ok(())
}

/// State transition function of `LastAccumulateOutputs`, assigning the accumulation output pairs
/// of the block into the state, yielding `θ′`. Returns the accumulate root, which can be consumed
/// by `transition_block_history_beefy_belt` STF.
pub async fn transition_last_accumulate_outputs(
    state_manager: Arc<StateManager>,
    accumulate_output_pairs: AccumulationOutputPairs,
) -> Result<AccumulateRoot, TransitionError> {
    let post_last_accumulate_outputs =
        LastAccumulateOutputs::from_output_pairs(accumulate_output_pairs);
    let accumulate_root = post_last_accumulate_outputs.clone().accumulate_root()?;
    state_manager
        .with_mut_last_accumulate_outputs(
            StateMut::Update,
            |outputs| -> Result<(), StateManagerError> {
                *outputs = post_last_accumulate_outputs;
                Ok(())
            },
        )
        .await?;
    Ok(accumulate_root)
}

/// State transition function of `BlockHistory.beefy_belt`, appending the accumulation outputs of
/// the block, `θ′`, into the append-only BEEFY belt. Consequently, `β_B′` is yielded.
pub async fn transition_block_history_beefy_belt(
    state_manager: Arc<StateManager>,
    accumulate_root: AccumulateRoot,
) -> Result<(), TransitionError> {
    state_manager
        .with_mut_block_history(
            StateMut::Update,
            |block_history| -> Result<(), StateManagerError> {
                block_history.beefy_belt.append(accumulate_root)?;
                Ok(())
            },
        )
        .await?;
    Ok(())
}

/// State transition function of `BlockHistory.history`, appending a new block history entry to the vector.
///
/// # Transitions
///
/// This handles the second state transition for `history` component of `BlockHistory`, yielding `β_H′`.
/// It constructs a new block history entry using the provided block header, work package hashes
/// from guarantee extrinsics, and the posterior accumulation result history MMR root (Super-peak of `β_B′`).
/// The new entry is then appended to the history, with the max length limit of `H`.
/// If the `history` becomes full, the oldest entry is removed.
pub async fn transition_block_history_append(
    state_manager: Arc<StateManager>,
    header_hash: BlockHeaderHash,
    mut reported_packages: Vec<ReportedWorkPackage>,
) -> Result<(), TransitionError> {
    let block_history = state_manager.get_block_history().await?;
    let accumulation_result_mmr_root = block_history.beefy_belt.super_peak()?; // β_B′

    // `report_packages` entries must be sorted
    reported_packages.sort_unstable();

    state_manager
        .with_mut_block_history(
            StateMut::Update,
            |history| -> Result<(), StateManagerError> {
                history.append(BlockHistoryEntry {
                    header_hash,
                    accumulation_result_mmr_root,
                    state_root: StateRoot::default(),
                    reported_packages,
                });
                Ok(())
            },
        )
        .await?;

    Ok(())
}
