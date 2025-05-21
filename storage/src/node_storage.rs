use crate::server_trait::NodeServerTrait;
use fr_block::{header_db::BlockHeaderDB, types::block::Block};
use fr_common::Hash32;
use fr_state::{error::StateManagerError, manager::StateManager, types::EffectiveValidators};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeStorageError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

// TODO: Add storages for Block(Extrinsics), Shards, etc.
pub struct NodeStorage {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
}

impl NodeServerTrait for NodeStorage {
    fn get_blocks(
        &self,
        _header_hash: Hash32,
        _ascending_excl: bool,
        _max_blocks: u32,
    ) -> Vec<Block> {
        // FIXME: unimplemented!()
        vec![Block::default(), Block::default()]
    }
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

    /// Gets effective validators of the previous, current and the next epoch.
    pub async fn effective_validators(&self) -> Result<EffectiveValidators, NodeStorageError> {
        let past_set = self.state_manager.get_past_set().await?;
        let active_set = self.state_manager.get_active_set().await?;
        let staging_set = self.state_manager.get_staging_set().await?;
        Ok(EffectiveValidators {
            past_set,
            active_set,
            staging_set,
        })
    }
}
