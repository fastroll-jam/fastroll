use rjam_codec::JamCodecError;
use rjam_crypto::CryptoError;
use rjam_state::StateManagerError;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum ExtrinsicValidationError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
}
