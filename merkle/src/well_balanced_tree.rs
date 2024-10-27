use crate::common::{node, MerkleError};
use rjam_common::{Hash32, Octets};
use rjam_crypto::{hash, octets_to_hash32, CryptoError, Hasher};
use std::marker::PhantomData;

/// Well-balanced binary Merkle Tree representation.
pub struct WellBalancedMerkleTree<H: Hasher> {
    pub root: Hash32,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> WellBalancedMerkleTree<H> {
    /// Constructs a new WellBalancedMerkleTree and returns the tree
    pub fn new(data: &[Octets]) -> Result<Self, MerkleError> {
        let root = Self::compute_root(data)?;
        Ok(Self {
            root,
            _hasher: PhantomData,
        })
    }

    /// Computes the root of the well-balanced Merkle tree
    pub fn compute_root(data: &[Octets]) -> Result<Hash32, MerkleError> {
        if data.len() == 1 {
            return Ok(hash::<H>(&data[0])?);
        }

        octets_to_hash32(&node::<H>(data)?).ok_or(MerkleError::CryptoError(CryptoError::HashError))
    }
}
