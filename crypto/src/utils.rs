use crate::{CryptoError, IetfVrfSignature, RingVrfSignature};
use ark_vrf::reexports::ark_serialize::CanonicalDeserialize;
use blake2::{digest::consts::U32, Blake2b, Digest};
use rjam_common::{BandersnatchRingVrfSig, BandersnatchSig, Hash32};

pub type Blake2b256 = Blake2b<U32>;
pub type Keccak256 = sha3::Keccak256;

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
        let mut hasher = Self::new();
        hasher.update(value);
        let result = hasher.finalize();
        result
            .as_slice()
            .try_into()
            .map(Hash32::new)
            .map_err(|_| CryptoError::Blake2bHashError)
    }
}

impl Hasher for Keccak256 {
    fn hash(value: &[u8]) -> Result<Hash32, CryptoError> {
        let mut hasher = Self::new();
        hasher.update(value);
        let result = hasher.finalize();
        result
            .as_slice()
            .try_into()
            .map(Hash32::new)
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

pub fn octets_to_hash32(value: &[u8]) -> Option<Hash32> {
    value.try_into().map(Hash32::new).ok()
}

/// `Y` hash output function for a VRF signature
pub fn entropy_hash_ietf_vrf(signature_bytes: &BandersnatchSig) -> Hash32 {
    let signature: IetfVrfSignature =
        IetfVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ietf_vrf_internal(&signature)
}

fn entropy_hash_ietf_vrf_internal(signature: &IetfVrfSignature) -> Hash32 {
    signature.output_hash()
}

/// `Y` hash output function for an anonymous RingVRF signature
pub fn entropy_hash_ring_vrf(signature_bytes: &BandersnatchRingVrfSig) -> Hash32 {
    let signature: RingVrfSignature =
        RingVrfSignature::deserialize_compressed(&signature_bytes[..]).unwrap();
    entropy_hash_ring_vrf_internal(&signature)
}

fn entropy_hash_ring_vrf_internal(signature: &RingVrfSignature) -> Hash32 {
    signature.output_hash()
}
