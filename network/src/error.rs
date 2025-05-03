use rjam_state::error::StateManagerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}
