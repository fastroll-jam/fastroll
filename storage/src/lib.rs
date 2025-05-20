//! Storage Interface
use fr_block::header_db::BlockHeaderDB;
use fr_state::{error::StateManagerError, manager::StateManager};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeStorageError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

// TODO: Add storages for Block, Shards, etc.
pub struct NodeStorage {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
}

impl NodeStorage {
    pub fn new(state_manager: Arc<StateManager>, header_db: Arc<BlockHeaderDB>) -> Self {
        Self {
            state_manager,
            header_db,
        }
    }

    pub fn state_manager(&self) -> Arc<StateManager> {
        self.state_manager.clone()
    }

    pub fn header_db(&self) -> Arc<BlockHeaderDB> {
        self.header_db.clone()
    }
}
