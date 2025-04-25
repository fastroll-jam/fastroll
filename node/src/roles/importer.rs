use rjam_block::types::{
    block::{Block, BlockHeader},
    extrinsics::Extrinsics,
};

#[allow(dead_code)]
pub(crate) struct MockPeerNode;
impl MockPeerNode {
    #[allow(dead_code)]
    pub(crate) fn default_block() -> Block {
        Block {
            header: BlockHeader::default(),
            extrinsics: Extrinsics::default(),
        }
    }
}
