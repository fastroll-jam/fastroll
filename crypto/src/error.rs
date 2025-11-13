use ark_vrf::reexports::ark_serialize::SerializationError;
use ed25519_consensus::Error as Ed25519Error;
use fr_codec::JamCodecError;
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
    #[error("Malformed validator metadata")]
    MalformedValidatorMetadata,
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("Ed25519Error: {0}")]
    Ed25519Error(#[from] Ed25519Error),
    #[error("SerializationError: {0}")]
    SerializationError(#[from] SerializationError),
}
