use crate::common::{node, MerkleError};
use fr_common::MerkleRoot;
use fr_crypto::{
    error::CryptoError,
    hash::{hash, octets_to_hash32, Hasher},
};
use std::marker::PhantomData;

/// Well-balanced binary Merkle Tree.
pub struct WellBalancedMerkleTree<H: Hasher> {
    pub root: MerkleRoot,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> WellBalancedMerkleTree<H> {
    /// Computes the root of the well-balanced Merkle tree
    pub fn compute_root(data: &[Vec<u8>]) -> Result<MerkleRoot, MerkleError> {
        if data.is_empty() {
            return Ok(MerkleRoot::default());
        }
        if data.len() == 1 {
            return Ok(hash::<H>(&data[0])?);
        }
        octets_to_hash32(&node::<H, Vec<u8>>(data)?)
            .ok_or(MerkleError::CryptoError(CryptoError::HashError))
    }
}
