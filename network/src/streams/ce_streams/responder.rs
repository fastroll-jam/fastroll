use crate::{
    streams::{
        ce_streams::{
            block_request::{BlockRequest, BlockRequestInitArgs},
            CeStream,
        },
        stream_kinds::CeStreamKind,
    },
    types::CHUNK_SIZE,
};
use fr_codec::prelude::*;
use fr_storage::node_storage::NodeStorage;
use std::sync::Arc;

pub struct CeStreamResponder;
impl CeStreamResponder {
    pub async fn run(
        stream_kind: CeStreamKind,
        mut send_stream: quinn::SendStream,
        mut recv_stream: quinn::RecvStream,
        node_storage: Arc<NodeStorage>,
    ) {
        match stream_kind {
            CeStreamKind::BlockRequest => {
                let mut init_args_bytes: &[u8] =
                    match recv_stream.read_chunk(CHUNK_SIZE, true).await {
                        Ok(Some(chunk)) => &chunk.bytes.clone(),
                        Ok(None) => {
                            tracing::warn!("[CE128] Stream closed");
                            return;
                        }
                        Err(e) => {
                            tracing::error!("[CE128] Failed to read block request: {e}");
                            return;
                        }
                    };

                let Ok(init_args) = BlockRequestInitArgs::decode(&mut init_args_bytes) else {
                    tracing::error!("[CE128] Failed to decode BlockRequestInitArgs");
                    return;
                };

                if let Err(e) =
                    BlockRequest::process_and_respond(&mut send_stream, &node_storage, init_args)
                        .await
                {
                    tracing::error!("[CE128] Failed to process Block Request: {e}");
                }
            }
            _ => {
                unimplemented!()
            }
        }
    }
}
