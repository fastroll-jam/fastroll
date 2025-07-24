use crate::common::{node, MerkleError};
use fr_common::{Hash32, MerkleRoot};
use fr_crypto::{error::CryptoError, hash, octets_to_hash32, Blake2b256, Hasher};
use std::marker::PhantomData;

/// Constant-depth binary Merkle Tree.
pub struct ConstantDepthMerkleTree<H: Hasher> {
    pub root: MerkleRoot,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> ConstantDepthMerkleTree<H> {
    /// A constancy preprocessor function (_`C`_) which hashes all data items with a prefix
    /// and then pads the overall size to the next power of two with the zero hash.
    fn constancy_preprocess(data: &[Vec<u8>]) -> Result<Vec<Hash32>, MerkleError> {
        const PREFIX: &[u8] = b"leaf";

        if data.is_empty() {
            return Ok(vec![Hash32::default()]);
        }

        let output_len = data.len().next_power_of_two();
        let mut output = data
            .iter()
            .map(|item| {
                let hash_input = [PREFIX, item].concat();
                hash::<H>(&hash_input).expect("Hashing blobs should be successful")
            })
            .collect::<Vec<_>>();

        output.resize(output_len, Hash32::default());
        Ok(output)
    }

    /// Computes the root of the constant-depth Merkle tree
    pub fn compute_root(data: &[Vec<u8>]) -> Result<MerkleRoot, MerkleError> {
        if data.is_empty() {
            return Ok(MerkleRoot::default());
        }
        let data_with_constancy = Self::constancy_preprocess(data)?
            .into_iter()
            .map(|hash| hash.to_vec())
            .collect::<Vec<_>>();
        octets_to_hash32(&node::<H>(&data_with_constancy)?)
            .ok_or(MerkleError::CryptoError(CryptoError::HashError))
    }
}

/// Return hashes of all leaves of a subtree page of size 2^x (depth of x).
pub fn subtree_page_leaf_hashes(
    data: &[Vec<u8>],
    page_idx: usize,
    page_depth: usize,
) -> Vec<Hash32> {
    const PREFIX: &[u8] = b"leaf";
    let page_size = 2usize.pow(page_depth as u32);
    let start_idx = page_size * page_idx;
    let end_idx = data.len().min(start_idx + page_size);
    data[start_idx..end_idx]
        .iter()
        .map(|data_item| {
            hash::<Blake2b256>(&[PREFIX, data_item].concat())
                .expect("Hashing blobs should be successful")
        })
        .collect::<Vec<_>>()
}
