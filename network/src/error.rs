use fr_block::types::block::BlockHeaderError;
use fr_state::error::StateManagerError;
use quinn::{ConnectError, ConnectionError, ReadToEndError, WriteError};
use thiserror::Error;
use tokio::{sync::mpsc::error::SendError, task::JoinError};

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("quinn ConnectError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("quinn ConnectError: {0}")]
    ConnectError(#[from] ConnectError),
    #[error("quinn ConnectionError: {0}")]
    ConnectionError(#[from] ConnectionError),
    #[error("quinn WriteError: {0}")]
    WriteError(#[from] WriteError),
    #[error("quinn ReadToEndError: {0}")]
    ReadToEndError(#[from] ReadToEndError),
    #[error("tokio JoinError: {0}")]
    JoinError(#[from] JoinError),
    #[error("tokio SendError<Vec<u8>>: {0}")]
    SendError(#[from] SendError<Vec<u8>>),
    #[error("Invalid local address")]
    InvalidLocalAddr,
    #[error("Invalid peer address format: should be SocketAddrV6")]
    InvalidPeerAddrFormat,
    #[error("Invalid UP stream kind value: {0}")]
    InvalidUpStreamKind(u8),
    #[error("Invalid CE stream kind value: {0}")]
    InvalidCeStreamKind(u8),
    #[error("The socket address is not a known validator peer")]
    PeerSocketAddrNotFound,
    #[error("A connection with the peer is not yet established")]
    PeerConnectionNotFound,
}
