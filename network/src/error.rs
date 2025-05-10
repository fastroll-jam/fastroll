use fr_state::error::StateManagerError;
use quinn::{ConnectError, ConnectionError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("quinn ConnectError: {0}")]
    ConnectError(#[from] ConnectError),
    #[error("quinn ConnectionError: {0}")]
    ConnectionError(#[from] ConnectionError),
    #[error("Invalid local address")]
    InvalidLocalAddr,
    #[error("The Ed25519 public key is not registered as a network validator peer")]
    ValidatorPeerKeyNotFound,
}
