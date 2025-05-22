use crate::{
    jam_node::JamNode,
    roles::{
        author::{BlockAuthor, BlockAuthorError},
        manager::{RoleManager, RoleManagerError},
    },
};
use fr_block::{header_db::BlockHeaderDBError, types::block::BlockHeaderError, xt_db::XtDBError};
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
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("XtDBError: {0}")]
    XtDBError(#[from] XtDBError),
    #[error("BlockAuthorError: {0}")]
    BlockAuthorError(#[from] BlockAuthorError),
}

/// Authors or imports a new block for the current timeslot.
pub async fn extend_chain(
    jam_node: Arc<JamNode>,
    new_timeslot: &Timeslot,
) -> Result<(), ChainExtensionError> {
    if RoleManager::is_author_of_slot(
        jam_node.storage().state_manager(),
        jam_node.local_node_info().clone(),
        new_timeslot,
    )
    .await?
    {
        tracing::info!("✍️ Role: Author");
        let mut author = BlockAuthor::new(
            jam_node
                .curr_epoch_validator_index
                .expect("Epoch validator index should be set"),
            jam_node.local_node_info().clone(),
        )?;

        let (new_block, post_state_root) = author.author_block(jam_node.storage()).await?;
        tracing::info!(
            "🎁 Authored a new block ({}) (slot: {})",
            new_block.header.hash()?,
            new_block.header.timeslot_index()
        );
        tracing::trace!(
            "Header: {}\nXts: {:?} post state root: {}",
            new_block.header,
            new_block.extrinsics,
            post_state_root
        );

        let storage = jam_node.storage();

        // TODO: proper block finalization
        let new_header = new_block.header;
        storage.header_db().set_best_header(new_header.clone());
        storage
            .header_db()
            .commit_header(new_header.clone())
            .await?;

        storage
            .xt_db()
            .set_xt(new_header.extrinsic_hash(), new_block.extrinsics)
            .await?;

        // Note: For simplicity, announce the block to all peers in the network.
        // TODO: Announce to neighbors in the grid structure as per JAMNP
        jam_node
            .network_manager()
            .announce_block_to_all_peers(&new_header)
            .await?;

        Ok(())
    } else {
        tracing::info!("👂 Role: Importer");
        Ok(())
    }
}
