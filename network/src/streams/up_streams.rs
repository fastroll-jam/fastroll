use crate::{
    error::NetworkError,
    streams::stream_kinds::UpStreamKind,
    types::{BlockAnnouncement, CHUNK_SIZE},
};
use fr_codec::prelude::*;
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;

/// A UP stream handle that can request an outgoing UP stream message via `UpStreamHandler`.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct UpStreamHandle {
    stream_kind: UpStreamKind,
    mpsc_sender: mpsc::Sender<Vec<u8>>,
}

impl UpStreamHandle {
    pub fn new(stream_kind: UpStreamKind, mpsc_sender: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            stream_kind,
            mpsc_sender,
        }
    }

    pub async fn send_block_announcement(&self, blob: Vec<u8>) -> Result<(), NetworkError> {
        Ok(self.mpsc_sender.send(blob).await?)
    }
}

/// A UP stream handler that processes both incoming and outgoing UP stream messages.
pub struct UpStreamHandler;
impl UpStreamHandler {
    pub fn handle_up_stream(
        stream_kind: UpStreamKind,
        send_stream: SendStream,
        recv_stream: RecvStream,
        mpsc_recv: mpsc::Receiver<Vec<u8>>,
    ) {
        match stream_kind {
            UpStreamKind::BlockAnnouncement => {
                tokio::spawn(async move { Self::handle_incoming_stream(recv_stream).await });
                tokio::spawn(
                    async move { Self::handle_outgoing_stream(send_stream, mpsc_recv).await },
                );
            }
        }
    }

    async fn handle_incoming_stream(mut recv_stream: RecvStream) {
        loop {
            match recv_stream.read_chunk(CHUNK_SIZE, true).await {
                Ok(Some(chunk)) => {
                    let mut bytes: &[u8] = &chunk.bytes;
                    let Ok(block_announcement) = BlockAnnouncement::decode(&mut bytes) else {
                        tracing::error!("Failed to decode BlockAnnouncement");
                        continue;
                    };
                    tracing::info!("Received Block Announcement:\n{block_announcement}");
                    // TODO: send a block request to the author. connection handle required.
                }
                Ok(None) => {
                    tracing::warn!("[UP0] Stream closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("[UP0] Error receiving block announcement: {e}");
                    // TODO: re-connect to peers
                    break;
                }
            }
        }
    }

    async fn handle_outgoing_stream(
        mut send_stream: SendStream,
        mut mpsc_recv: mpsc::Receiver<Vec<u8>>,
    ) {
        while let Some(send_msg) = mpsc_recv.recv().await {
            if let Err(e) = send_stream.write_all(send_msg.as_slice()).await {
                tracing::error!("Error sending block announcement: {e}");
                break;
            }
            tracing::debug!("📣 Sent Block Announcement to peer");
        }
    }
}
