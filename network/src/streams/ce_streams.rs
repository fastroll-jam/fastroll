use crate::{error::NetworkError, streams::stream_kinds::CeStreamKind, types::CHUNK_SIZE};
use async_trait::async_trait;
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::Hash32;
use fr_storage::{node_storage::NodeStorage, server_trait::NodeServerTrait};

pub enum NodeRole {
    Node,
    Builder,
    Validator,
    Guarantor,
    Assurer,
    Auditor,
}

#[async_trait]
pub trait CeStream {
    const INITIATOR_ROLE: NodeRole;
    const ACCEPTOR_ROLE: NodeRole;
    const CE_STREAM_KIND: CeStreamKind;

    type InitArgs: JamEncode + JamDecode + Send;
    type RespArgs: JamEncode + JamDecode + Send;
    type Storage: NodeServerTrait + Sync;

    async fn initiate(conn: quinn::Connection, args: Self::InitArgs) -> Result<(), NetworkError>;

    async fn send_ce_request(
        send_stream: &mut quinn::SendStream,
        args: Self::InitArgs,
    ) -> Result<(), NetworkError> {
        let stream_id = send_stream.id();
        // Send a single-byte stream kind identifier to the peer so that it can accept the stream.
        let stream_kind_byte = vec![Self::CE_STREAM_KIND as u8];
        send_stream.write_all(&stream_kind_byte).await?;
        // Send a request
        send_stream.write_all(&args.encode()?).await?;
        // Close the stream
        send_stream.finish()?;
        tracing::info!("[CE128] Sent block request | {stream_id}");
        Ok(())
    }

    async fn process(
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<Self::RespArgs, NetworkError>;

    async fn respond(
        send_stream: &mut quinn::SendStream,
        args: Self::RespArgs,
    ) -> Result<(), NetworkError> {
        send_stream.write_all(args.encode()?.as_slice()).await?;
        Ok(())
    }

    async fn process_and_respond(
        send_stream: &mut quinn::SendStream,
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<(), NetworkError> {
        let resp_args = Self::process(storage, init_args).await?;
        Self::respond(send_stream, resp_args).await
    }
}

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
    type Storage = NodeStorage;

    async fn initiate(conn: quinn::Connection, args: Self::InitArgs) -> Result<(), NetworkError> {
        let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
        Self::send_ce_request(&mut send_stream, args).await?;
        let stream_id = recv_stream.id();
        match recv_stream.read_chunk(CHUNK_SIZE, true).await {
            Ok(Some(chunk)) => {
                let mut bytes: &[u8] = &chunk.bytes;
                let mut blocks = vec![];
                while let Ok(block) = Block::decode(&mut bytes) {
                    blocks.push(block);
                }
                tracing::info!(
                    "[CE128] Received blocks. Length: {} | {stream_id}",
                    blocks.len()
                );
            }
            Ok(None) => {
                tracing::warn!("[CE128] Stream closed | {stream_id}");
            }
            Err(e) => {
                tracing::error!("[CE128] Error receiving blocks: {e} | {stream_id}")
            }
        }
        Ok(())
    }

    async fn process(
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<Self::RespArgs, NetworkError> {
        let blocks = storage.get_blocks(
            init_args.header_hash,
            init_args.ascending_excl,
            init_args.max_blocks,
        );
        Ok(Self::RespArgs { blocks })
    }
}
