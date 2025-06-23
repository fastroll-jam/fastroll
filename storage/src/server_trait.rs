use crate::node_storage::NodeStorageError;
use async_trait::async_trait;
use fr_block::types::block::Block;
use fr_common::BlockHeaderHash;

/// Trait of node data server that specifies APIs required by the networking protocol.
#[async_trait]
pub trait NodeServerTrait {
    /// CE 128: Block request
    async fn get_blocks(
        &self,
        header_hash: BlockHeaderHash,
        ascending_excl: bool,
        max_blocks: u32,
    ) -> Result<Vec<Block>, NodeStorageError>;
}
