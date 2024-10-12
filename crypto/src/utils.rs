use crate::vrf::{IetfVrfSignature, RingVrfSignature};
use ark_ec_vrfs::prelude::{ark_serialize, ark_serialize::SerializationError};
use ark_serialize::CanonicalDeserialize;
use blake2::{digest::consts::U32, Blake2b, Digest};
use rjam_common::{BandersnatchRingVrfSignature, BandersnatchSignature, Hash32, Octets};
use sha3::Keccak256;
use thiserror::Error;

pub type Blake2b256 = Blake2b<U32>;

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
    #[error("Serialization Error")]
    SerializationError(SerializationError),
    #[error("VRF proof verification Error")]
    VrfVerificationFailed,
}

/// Trait for different types of hasher
pub trait Hasher {
    fn hash(value: &[u8]) -> Result<Hash32, CryptoError>;

    fn hash_prefix_4(value: &[u8]) -> Result<[u8; 4], CryptoError> {
        let hash = Self::hash(value)?;
        Ok(hash[..4].try_into().unwrap())
    }
}

impl Hasher for Blake2b256 {
    fn hash(value: &[u8]) -> Result<Hash32, CryptoError> {
        let mut hasher = Blake2b256::new();
        hasher.update(value);
        let result = hasher.finalize();
        result
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Blake2bHashError)
    }
}

impl Hasher for Keccak256 {
    fn hash(value: &[u8]) -> Result<Hash32, CryptoError> {
        let mut hasher = Keccak256::new();
        hasher.update(value);
        let result = hasher.finalize();
        result
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Keccak256HashError)
    }
}

/// Generic hash function
pub fn hash<H: Hasher>(value: &[u8]) -> Result<Hash32, CryptoError> {
    H::hash(value)
}

pub fn hash_prefix_4<H: Hasher>(value: &[u8]) -> Result<[u8; 4], CryptoError> {
    H::hash_prefix_4(value)
}

pub fn octets_to_hash32(value: &Octets) -> Option<Hash32> {
    value.as_slice().try_into().ok()
}

// `Y` hash function for a VRF signature
pub fn entropy_hash_ietf_vrf(signature_bytes: &BandersnatchSignature) -> Hash32 {
    let signature: IetfVrfSignature =
        IetfVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ietf_vrf_internal(&signature)
}

fn entropy_hash_ietf_vrf_internal(signature: &IetfVrfSignature) -> Hash32 {
    signature.output_hash()
}

// `Y` hash function for an anonymous RingVRF signature
pub fn entropy_hash_ring_vrf(signature_bytes: &BandersnatchRingVrfSignature) -> Hash32 {
    let signature: RingVrfSignature =
        RingVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ring_vrf_internal(&signature)
}

fn entropy_hash_ring_vrf_internal(signature: &RingVrfSignature) -> Hash32 {
    signature.output_hash()
}
