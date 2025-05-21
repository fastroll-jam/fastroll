use crate::{error::NetworkError, streams::stream_kinds::CeStreamKind, types::CHUNK_SIZE};
use async_trait::async_trait;
use fr_block::types::block::Block;
use fr_codec::prelude::*;
use fr_common::Hash32;
use fr_storage::{node_storage::NodeStorage, server_trait::NodeServerTrait};
use std::fmt::Debug;

pub enum NodeRole {
    Node,
    Builder,
    Validator,
    Guarantor,
    Assurer,
    Auditor,
}

mod ce_stream_utils {
    use super::*;

    pub(super) async fn open_stream_and_request<T>(
        conn: quinn::Connection,
        args: T::InitArgs,
    ) -> Result<quinn::RecvStream, NetworkError>
    where
        T: CeStream + ?Sized,
    {
        let (mut send_stream, recv_stream) = conn.open_bi().await?;
        // Send a single-byte stream kind identifier to the peer so that it can accept the stream.
        let stream_kind_byte = vec![T::CE_STREAM_KIND as u8];
        send_stream.write_all(&stream_kind_byte).await?;
        // Send a request
        send_stream.write_all(&args.encode()?).await?;
        // Close the stream
        send_stream.finish()?;
        tracing::info!("[{}] Sent CE stream request", T::CE_STREAM_KIND);
        Ok(recv_stream)
    }

    pub(super) async fn respond<T>(
        send_stream: &mut quinn::SendStream,
        args: T::RespArgs,
    ) -> Result<(), NetworkError>
    where
        T: CeStream + ?Sized,
    {
        send_stream.write_all(args.encode()?.as_slice()).await?;
        Ok(())
    }
}

#[async_trait]
pub trait CeStream {
    const INITIATOR_ROLE: NodeRole;
    const ACCEPTOR_ROLE: NodeRole;
    const CE_STREAM_KIND: CeStreamKind;

    type InitArgs: JamEncode + JamDecode + Send;
    type RespArgs: JamEncode + JamDecode + Send;
    type RespType;
    type Storage: NodeServerTrait + Sync;

    async fn initiate(conn: quinn::Connection, args: Self::InitArgs) -> Result<(), NetworkError> {
        let mut recv_stream = ce_stream_utils::open_stream_and_request::<Self>(conn, args).await?;
        match recv_stream.read_chunk(CHUNK_SIZE, true).await {
            Ok(Some(chunk)) => {
                let mut bytes: &[u8] = &chunk.bytes;
                let _resp = Self::decode_response(&mut bytes);
                // TODO: handle response
                tracing::info!("[{}] Received respond", Self::CE_STREAM_KIND);
            }
            Ok(None) => {
                tracing::warn!("[{}] Stream closed", Self::CE_STREAM_KIND);
            }
            Err(e) => {
                tracing::error!("[{}] Error receiving blocks: {e}", Self::CE_STREAM_KIND)
            }
        }
        Ok(())
    }

    fn decode_response(bytes: &mut &[u8]) -> Self::RespType;

    async fn process(
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<Self::RespArgs, NetworkError>;

    async fn process_and_respond(
        send_stream: &mut quinn::SendStream,
        storage: &Self::Storage,
        init_args: Self::InitArgs,
    ) -> Result<(), NetworkError> {
        let resp_args = Self::process(storage, init_args).await?;
        ce_stream_utils::respond::<Self>(send_stream, resp_args).await
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
        let blocks = storage.get_blocks(
            init_args.header_hash,
            init_args.ascending_excl,
            init_args.max_blocks,
        );
        Ok(Self::RespArgs { blocks })
    }
}
