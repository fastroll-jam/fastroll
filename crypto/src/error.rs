use ark_vrf::reexports::ark_serialize::SerializationError;
use fr_common::CommonTypeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Public key has invalid format")]
    InvalidPubKeyFormat,
    #[error("General Hashing Error")]
    HashError,
    #[error("Blake2b Hashing Error")]
    Blake2bHashError,
    #[error("Keccak256 Hashing Error")]
    Keccak256HashError,
    #[error("Hash Conversion Error")]
    HashConversionError,
    #[error("Failed to find ring context resource")]
    RingContextResourceError,
    #[error("Failed to construct ring root")]
    RingRootError,
    #[error("Failed to decode Bandersnatch public key")]
    BandersnatchDecodeError,
    #[error("Invalid VRF input format")]
    InvalidVrfInput,
    #[error("VRF proof verification Error")]
    VrfVerificationFailed,
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("Ed25519SigError: {0}")]
    Ed25519SigError(#[from] ed25519_dalek::SignatureError),
    #[error("SerializationError: {0}")]
    SerializationError(#[from] SerializationError),
}
