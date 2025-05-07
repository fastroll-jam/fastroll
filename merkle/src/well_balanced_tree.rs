use crate::common::{node, MerkleError};
use fr_common::Hash32;
use fr_crypto::{
    error::CryptoError,
    hash::{hash, octets_to_hash32, Hasher},
};
use std::marker::PhantomData;

/// Well-balanced binary Merkle Tree representation.
pub struct WellBalancedMerkleTree<H: Hasher> {
    pub root: Hash32,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> WellBalancedMerkleTree<H> {
    /// Computes the root of the well-balanced Merkle tree
    pub fn compute_root(data: &[Vec<u8>]) -> Result<Hash32, MerkleError> {
        if data.is_empty() {
            return Ok(Hash32::default());
        }
        if data.len() == 1 {
            return Ok(hash::<H>(&data[0])?);
        }
        octets_to_hash32(&node::<H>(data)?).ok_or(MerkleError::CryptoError(CryptoError::HashError))
    }
}
