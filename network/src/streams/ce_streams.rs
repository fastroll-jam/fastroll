use crate::{error::NetworkError, streams::stream_kinds::CeStreamKind, types::CHUNK_SIZE};
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::Hash32;
use std::future::Future;

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

    fn initiate(
        conn: quinn::Connection,
        args: Self::InitArgs,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;

    // TODO: Add a common DB interface handle as a param
    fn process(
        init_args: Self::InitArgs,
    ) -> impl Future<Output = Result<Self::RespArgs, NetworkError>> + Send;

    fn respond(args: Self::RespArgs) -> impl Future<Output = Result<(), NetworkError>> + Send;
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestInitArgs {
    header_hash: Hash32,
    ascending: bool,
    maximum_blocks: u32,
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct BlockRequestRespArgs {
    pub blocks: Vec<Block>,
}

pub struct BlockRequest;
impl CeStream for BlockRequest {
    const INITIATOR_ROLE: NodeRole = NodeRole::Node;
    const ACCEPTOR_ROLE: NodeRole = NodeRole::Node;

    type InitArgs = BlockRequestInitArgs;
    type RespArgs = BlockRequestRespArgs;

    async fn initiate(conn: quinn::Connection, args: Self::InitArgs) -> Result<(), NetworkError> {
        let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

        // Send a single-byte stream kind identifier to the peer so that it can accept the stream.
        let stream_kind = CeStreamKind::BlockRequest;
        let stream_kind_byte = vec![stream_kind as u8];
        send_stream.write_all(&stream_kind_byte).await?;

        // Send a request
        send_stream.write_all(&args.encode()?).await?;
        // Close the stream
        send_stream.finish()?;

        match recv_stream.read_chunk(CHUNK_SIZE, true).await {
            Ok(Some(chunk)) => {
                let mut bytes: &[u8] = &chunk.bytes;
                let mut blocks = vec![];
                while let Ok(block) = Block::decode(&mut bytes) {
                    blocks.push(block);
                }
            }
            Ok(None) => {
                tracing::warn!("[CE128] Stream closed");
            }
            Err(e) => {
                tracing::error!("[CE128] Error receiving blocks: {e}")
            }
        }
        Ok(())
    }

    async fn process(_init_args: Self::InitArgs) -> Result<Self::RespArgs, NetworkError> {
        unimplemented!()
    }

    async fn respond(args: Self::RespArgs) -> Result<(), NetworkError> {
        let _data = args.encode()?;
        Ok(())
    }
}
