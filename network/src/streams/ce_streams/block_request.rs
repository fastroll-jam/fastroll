//! CE 128 Block Request

use crate::{
    error::NetworkError,
    streams::{
        ce_streams::{CeStream, NodeRole},
        stream_kinds::CeStreamKind,
    },
};
use async_trait::async_trait;
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::Hash32;
use fr_storage::{node_storage::NodeStorage, server_trait::NodeServerTrait};

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestInitArgs {
    pub header_hash: Hash32,
    pub ascending_excl: bool,
    pub max_blocks: u32,
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestRespArgs {
    pub blocks: Vec<Block>,
}

pub struct BlockRequest;

#[async_trait]
impl CeStream for BlockRequest {
    const INITIATOR_ROLE: NodeRole = NodeRole::Node;
    const ACCEPTOR_ROLE: NodeRole = NodeRole::Node;
    const CE_STREAM_KIND: CeStreamKind = CeStreamKind::BlockRequest;

    type InitArgs = BlockRequestInitArgs;
    type RespArgs = BlockRequestRespArgs;
    type RespType = Vec<Block>;
    type Storage = NodeStorage;

    fn decode_response(bytes: &mut &[u8]) -> Self::RespType {
        let mut blocks = vec![];
        while let Ok(block) = Block::decode(bytes) {
            blocks.push(block);
        }
        blocks
    }

    async fn process(
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<Self::RespArgs, NetworkError> {
        let blocks = storage
            .get_blocks(
                init_args.header_hash,
                init_args.ascending_excl,
                init_args.max_blocks,
            )
            .await?;
        Ok(Self::RespArgs { blocks })
    }

    fn encode_response_args(args: Self::RespArgs) -> Result<Vec<u8>, NetworkError> {
        let blocks_count = args.blocks.len();
        Ok(args.blocks.encode_fixed(blocks_count)?)
    }
}
