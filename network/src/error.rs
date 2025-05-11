use fr_state::error::StateManagerError;
use quinn::{ConnectError, ConnectionError, WriteError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("quinn ConnectError: {0}")]
    ConnectError(#[from] ConnectError),
    #[error("quinn ConnectionError: {0}")]
    ConnectionError(#[from] ConnectionError),
    #[error("quinn WriteError: {0}")]
    WriteError(#[from] WriteError),
    #[error("Invalid local address")]
    InvalidLocalAddr,
    #[error("Invalid peer address format: should be SocketAddrV6")]
    InvalidPeerAddrFormat,
    #[error("The Ed25519 public key is not registered as a network validator peer")]
    ValidatorPeerKeyNotFound,
}
