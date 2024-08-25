use crate::vrf::{IetfVrfSignature, RingVrfSignature};
use ark_ec_vrfs::prelude::{ark_serialize, ark_serialize::SerializationError};
use ark_serialize::CanonicalDeserialize;
use blake2::{digest::consts::U32, Blake2b, Digest};
use jam_common::{BandersnatchRingVrfProof, BandersnatchSignature, Hash32};
use std::array::TryFromSliceError;
use thiserror::Error;

type Blake2b256 = Blake2b<U32>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Blake2b Hashing Error")]
    Blake2bHashError,
    #[error("Hash Conversion Error")]
    HashConversionError,
    #[error("Failed to find ring context resource")]
    RingContextResourceError,
    #[error("Serialization Error")]
    SerializationError(SerializationError),
}

// Black2b-256 hash
pub fn blake2b_256(value: &[u8]) -> Result<Hash32, CryptoError> {
    let mut hasher = Blake2b256::new();
    hasher.update(value);
    let result = hasher.finalize();
    result
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Blake2bHashError)
}

pub fn blake2b_256_first_4bytes(value: &[u8]) -> Result<[u8; 4], CryptoError> {
    let hash = blake2b_256(value)?;
    Ok(hash[..4].try_into().unwrap())
}

// `Y` hash function for a VRF signature
pub fn entropy_hash_ietf_vrf(signature_bytes: &BandersnatchSignature) -> Hash32 {
    let signature: IetfVrfSignature =
        IetfVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ietf_vrf_internal(&signature)
}

fn entropy_hash_ietf_vrf_internal(signature: &IetfVrfSignature) -> Hash32 {
    signature.output.hash()[..32].try_into().unwrap()
}

// `Y` hash function for an anonymous RingVRF signature
pub fn entropy_hash_ring_vrf(signature_bytes: &BandersnatchRingVrfProof) -> Hash32 {
    let signature: RingVrfSignature =
        RingVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ring_vrf_internal(&signature)
}

fn entropy_hash_ring_vrf_internal(signature: &RingVrfSignature) -> Hash32 {
    signature.output.hash()[..32].try_into().unwrap()
}
