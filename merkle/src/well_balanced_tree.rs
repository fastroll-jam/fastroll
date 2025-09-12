use crate::common::{node, MerkleError};
use fr_codec::prelude::*;
use fr_common::{Hash32, MerkleRoot};
use fr_crypto::hash::{hash, Hasher};
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
        let root_data = node::<H, Vec<u8>>(data)?;
        Ok(Hash32::decode(&mut root_data.as_slice())?)
    }
}
