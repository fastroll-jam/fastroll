use ark_ec_vrfs::reexports::ark_serialize::SerializationError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
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
    #[error("Serialization Error")]
    SerializationError(SerializationError),
    #[error("VRF proof verification Error")]
    VrfVerificationFailed,
}
