use crate::error::NetworkError;
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::Hash32;

pub enum NodeRole {
    Node,
    Builder,
    Validator,
    Guarantor,
    Assurer,
    Auditor,
}

pub trait CeStream {
    const INITIATOR_ROLE: NodeRole;
    const ACCEPTOR_ROLE: NodeRole;

    type InitArgs: JamEncode + JamDecode;
    type RespArgs: JamEncode + JamDecode;

    fn initiate(args: Self::InitArgs) -> Result<(), NetworkError>;

    fn respond(args: Self::RespArgs) -> Result<(), NetworkError>;
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestInitArgs {
    header_hash: Hash32,
    ascending: bool,
    maximum_blocks: u32,
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestRespArgs {
    block: Block,
}

pub struct BlockRequest;
impl CeStream for BlockRequest {
    const INITIATOR_ROLE: NodeRole = NodeRole::Node;
    const ACCEPTOR_ROLE: NodeRole = NodeRole::Node;

    type InitArgs = BlockRequestInitArgs;
    type RespArgs = BlockRequestRespArgs;

    fn initiate(args: Self::InitArgs) -> Result<(), NetworkError> {
        let _data = args.encode()?;
        Ok(())
    }

    fn respond(args: Self::RespArgs) -> Result<(), NetworkError> {
        let _data = args.encode()?;
        Ok(())
    }
}
