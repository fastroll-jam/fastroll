use crate::server_trait::NodeServerTrait;
use async_trait::async_trait;
use fr_block::{
    header_db::{BlockHeaderDB, BlockHeaderDBError},
    post_state_root_db::PostStateRootDB,
    types::block::Block,
    xt_db::{XtDB, XtDBError},
};
use fr_common::{BlockHeaderHash, ByteEncodable};
use fr_config::StorageConfig;
use fr_db::core::core_db::{CoreDB, CoreDBError};
use fr_state::{error::StateManagerError, manager::StateManager, types::EffectiveValidators};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeStorageError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("XtDBError: {0}")]
    XtDBError(#[from] XtDBError),
    #[error("Header with hash {0} not found from the HeaderDB")]
    HeaderNotFoundFromDB(String),
    #[error("Xts with hash {0} not found from the XtDB")]
    XtsNotFoundFromDB(String),
}

// TODO: Add storages for Shards, etc.
pub struct NodeStorage {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
    xt_db: Arc<XtDB>,
    post_state_root_db: Arc<PostStateRootDB>,
}

#[async_trait]
impl NodeServerTrait for NodeStorage {
    async fn get_blocks(
        &self,
        header_hash: BlockHeaderHash,
        ascending_excl: bool,
        max_blocks: u32,
    ) -> Result<Vec<Block>, NodeStorageError> {
        if !ascending_excl && max_blocks == 1 {
            let block = self.get_block(&header_hash).await?;
            Ok(vec![block])
        } else {
            unimplemented!()
        }
    }
}

impl Default for NodeStorage {
    fn default() -> Self {
        Self::new(StorageConfig::default())
            .expect("Failed to initialize NodeStorage with default config")
    }
}

impl NodeStorage {
    pub fn new(cfg: StorageConfig) -> Result<Self, NodeStorageError> {
        let core_db = Arc::new(CoreDB::open(
            cfg.path.clone(),
            StorageConfig::rocksdb_opts(),
            StorageConfig::cf_descriptors(),
        )?);
        let header_db = Arc::new(BlockHeaderDB::new(
            core_db.clone(),
            cfg.cfs.header_db.cf_name,
            cfg.cfs.header_db.cache_size,
        ));
        let xt_db = Arc::new(XtDB::new(
            core_db.clone(),
            cfg.cfs.xt_db.cf_name,
            cfg.cfs.xt_db.cache_size,
        ));
        let post_state_root_db = Arc::new(PostStateRootDB::new(
            core_db.clone(),
            cfg.cfs.post_state_root_db.cf_name,
            cfg.cfs.post_state_root_db.cache_size,
        ));
        let state_manager = Arc::new(StateManager::from_core_db(core_db, &cfg));
        Ok(Self {
            state_manager,
            header_db,
            xt_db,
            post_state_root_db,
        })
    }

    pub fn state_manager(&self) -> Arc<StateManager> {
        self.state_manager.clone()
    }

    pub fn header_db(&self) -> Arc<BlockHeaderDB> {
        self.header_db.clone()
    }

    pub fn xt_db(&self) -> Arc<XtDB> {
        self.xt_db.clone()
    }

    pub fn post_state_root_db(&self) -> Arc<PostStateRootDB> {
        self.post_state_root_db.clone()
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

    async fn get_block(&self, header_hash: &BlockHeaderHash) -> Result<Block, NodeStorageError> {
        let header = self
            .header_db
            .get_header(header_hash)
            .await?
            .ok_or(NodeStorageError::HeaderNotFoundFromDB(header_hash.to_hex()))?;
        let xt_hash = header.extrinsic_hash();
        let extrinsics = self
            .xt_db
            .get_xt(xt_hash)
            .await?
            .ok_or(NodeStorageError::XtsNotFoundFromDB(xt_hash.to_hex()))?;
        Ok(Block { header, extrinsics })
    }
}
