use crate::common::Hash32;
use blake2::{digest::consts::U32, Blake2b, Digest};
use thiserror::Error;

type Blake2b256 = Blake2b<U32>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Blake2b Hashing Error")]
    Blake2bHashError,
}

// Black2b-256 hash
pub(crate) fn blake2b_256(value: &[u8]) -> Result<Hash32, CryptoError> {
    let mut hasher = Blake2b256::new();
    hasher.update(value);
    let result = hasher.finalize();
    result
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Blake2bHashError)
}

pub(crate) fn blake2b_256_first_4bytes(value: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hash = blake2b_256(value)?;
    Ok(hash[..4].try_into().unwrap())
}
