use fr_block::types::block::BlockHeaderError;
use fr_codec::JamCodecError;
use fr_storage::node_storage::NodeStorageError;
use quinn::{
    ClosedStream, ConnectError, ConnectionError, ReadExactError, ReadToEndError, WriteError,
};
use thiserror::Error;
use tokio::{sync::mpsc::error::SendError, task::JoinError};

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("NodeStorageError: {0}")]
    NodeStorageError(#[from] NodeStorageError),
    #[error("quinn ConnectError: {0}")]
    ConnectError(#[from] ConnectError),
    #[error("quinn ConnectionError: {0}")]
    ConnectionError(#[from] ConnectionError),
    #[error("quinn ClosedStream: {0}")]
    ClosedStream(#[from] ClosedStream),
    #[error("quinn WriteError: {0}")]
    WriteError(#[from] WriteError),
    #[error("quinn ReadToEndError: {0}")]
    ReadToEndError(#[from] ReadToEndError),
    #[error("quinn ReadExactError: {0}")]
    ReadExactError(#[from] ReadExactError),
    #[error("tokio JoinError: {0}")]
    JoinError(#[from] JoinError),
    #[error("tokio SendError<Vec<u8>>: {0}")]
    SendError(#[from] SendError<Vec<u8>>),
    #[error("Invalid local address")]
    InvalidLocalAddr,
    #[error("Invalid peer address format: should be SocketAddrV6")]
    InvalidPeerAddrFormat,
    #[error("Invalid stream kind value: {0}")]
    InvalidStreamKind(u8),
    #[error("Invalid UP stream kind value: {0}")]
    InvalidUpStreamKind(u8),
    #[error("Invalid CE stream kind value: {0}")]
    InvalidCeStreamKind(u8),
    #[error("The socket address is not a known validator peer")]
    PeerSocketAddrNotFound,
    #[error("A connection with the peer is not yet established")]
    PeerConnectionNotFound,
    #[error("Failed to receive respond from CE stream")]
    CeStreamRecvError,
}
