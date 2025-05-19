use crate::{
    jam_node::JamNode,
    roles::{
        author::{BlockAuthor, BlockAuthorError},
        manager::RoleManagerError,
    },
};
use fr_network::error::NetworkError;
use fr_state::types::Timeslot;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainExtensionError {
    #[error("NetworkError: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("RoleManagerError: {0}")]
    RoleManagerError(#[from] RoleManagerError),
    #[error("BlockAuthorError: {0}")]
    BlockAuthorError(#[from] BlockAuthorError),
}

/// Authors or imports a new block for the current timeslot.
pub async fn extend_chain(
    jam_node: Arc<JamNode>,
    new_timeslot: &Timeslot,
) -> Result<(), ChainExtensionError> {
    if jam_node
        .role_manager
        .is_author_of_slot(new_timeslot)
        .await?
    {
        tracing::info!("✍️ Role: Author");
        let best_header = jam_node.header_db.get_best_header();
        let mut author = BlockAuthor::new(
            jam_node
                .curr_epoch_validator_index
                .expect("Epoch validator index should be set"),
            jam_node.local_node_info.clone(),
            jam_node.state_manager.clone(),
            best_header,
        )?;

        let (new_block, post_state_root) = author.author_block(jam_node.header_db.clone()).await?;
        tracing::info!(
            "🎁 Authored a new block:\nHeader: {}\nXts: {:?} post state root: {}",
            new_block.header,
            new_block.extrinsics,
            post_state_root
        );

        // Note: For simplicity, announce the block to all peers in the network.
        // TODO: Announce to neighbors in the grid structure as per JAMNP
        jam_node
            .network_manager
            .announce_block_to_all_peers(&new_block.header)
            .await?;

        Ok(())
    } else {
        tracing::info!("👂 Role: Importer");
        Ok(())
    }
}
