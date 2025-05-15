use crate::{jam_node::JamNode, roles::manager::RoleManagerError};
use fr_state::types::Timeslot;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainExtensionError {
    #[error("RoleManagerError: {0}")]
    RoleManagerError(#[from] RoleManagerError),
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
        let _author_pub_key = &jam_node.local_node_info.validator_key.bandersnatch_key;
        let _best_header = jam_node.header_db.get_best_header();
        // let mut author = BlockAuthor::new
        Ok(())
    } else {
        tracing::info!("👂 Role: Importer");
        Ok(())
    }
}
