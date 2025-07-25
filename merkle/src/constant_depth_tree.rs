use crate::common::{node, trace, MerkleError};
use fr_common::{Hash32, MerkleRoot};
use fr_crypto::{error::CryptoError, hash, octets_to_hash32, Hasher};
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
        octets_to_hash32(&node::<H, Vec<u8>>(&data_with_constancy)?)
            .ok_or(MerkleError::CryptoError(CryptoError::HashError))
    }

    /// Returns Merkle path (path nodes and all relevant sibling nodes) from root to a single page of
    /// size 2^x (depth of x).
    pub fn single_page_justification(
        data: &[Vec<u8>],
        page_idx: usize,
        page_depth: usize,
    ) -> Result<Vec<Hash32>, MerkleError> {
        let mut trace = trace::<H, Hash32>(
            &Self::constancy_preprocess(data)?,
            2usize.pow(page_depth as u32) * page_idx,
        )?;
        let whole_tree_depth = data.len().next_power_of_two().ilog2() as usize;
        let justification_length = whole_tree_depth.saturating_sub(page_depth);
        trace.resize(justification_length, Hash32::default());
        Ok(trace)
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
                hash::<H>(&[PREFIX, data_item].concat())
                    .expect("Hashing blobs should be successful")
            })
            .collect::<Vec<_>>()
    }
}
