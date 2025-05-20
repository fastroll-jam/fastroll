use fr_block::types::block::Block;
use fr_common::Hash32;

/// Trait of node data server that specifies APIs required by the networking protocol.
pub trait NodeServerTrait {
    /// CE 128: Block request
    fn get_blocks(&self, header_hash: Hash32, ascending_excl: bool, max_blocks: u32) -> Vec<Block>;
}
