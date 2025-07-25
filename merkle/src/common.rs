use fr_codec::JamCodecError;
use fr_common::{ByteEncodable, Hash32};
use fr_crypto::{
    error::CryptoError,
    hash::{hash, Hasher},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// A trait for types that can be used as data elements in merkle tree construction.
pub(crate) trait MerkleData: ByteEncodable + Clone {
    fn merkle_default() -> Self;
    fn from_hash<H: Hasher>(hash: Hash32) -> Self;
}

impl MerkleData for Vec<u8> {
    fn merkle_default() -> Self {
        Hash32::default().to_vec()
    }

    fn from_hash<H: Hasher>(hash: Hash32) -> Self {
        hash.to_vec()
    }
}

impl MerkleData for Hash32 {
    fn merkle_default() -> Self {
        Hash32::default()
    }

    fn from_hash<H: Hasher>(hash: Hash32) -> Self {
        hash
    }
}

/// A recursive _`node`_ function which takes a sequence of blobs (of a specific length)
/// and returns either one of those blobs or a hash.
pub(crate) fn node<H: Hasher, T: MerkleData>(data: &[T]) -> Result<T, MerkleError> {
    const HASH_PREFIX: &[u8] = b"node";
    if data.is_empty() {
        return Ok(T::merkle_default());
    }
    if data.len() == 1 {
        return Ok(data[0].clone());
    }

    let left = node::<H, T>(&data[..data.len().div_ceil(2)])?;
    let right = node::<H, T>(&data[data.len().div_ceil(2)..])?;

    let hash_input = [HASH_PREFIX, left.as_slice(), right.as_slice()].concat();
    Ok(T::from_hash::<H>(hash::<H>(&hash_input)?))
}

/// The `P^S` function which splits the given data sequence into half and returns either of the
/// sub-sequences depending on the `select_idx_side` boolean flag.
///
/// If the flag is true, returns the sub-sequence where `idx` belongs to.
///
/// Note: Since this function is currently only used for constant-depth trees which have sequence of
/// hashes as input data, we're using slice of `Hash32` as input type.
fn split_and_select(data: &[Hash32], idx: usize, select_idx_side: bool) -> &[Hash32] {
    let mid = data.len().div_ceil(2);
    if (idx < mid) == select_idx_side {
        &data[..mid]
    } else {
        &data[mid..]
    }
}

/// The `P_I` function which returns 0 for indices in the first half of the data sequence,
/// or the midpoint for those in the second half.
///
/// Note: Since this function is currently only used for constant-depth trees which have sequence of
/// hashes as input data, we're using slice of `Hash32` as input type.
fn merkle_index_offset(data: &[Hash32], idx: usize) -> usize {
    let mid = data.len().div_ceil(2);
    if idx < mid {
        0
    } else {
        mid
    }
}

/// A recursive _`trace`_ function which takes a sequence of blobs (of a specific length)
/// and an item index within that sequence. It then returns, from top to bottom, each sibling node
/// encountered while navigating the tree to reach the leaf corresponding to that item.
///
/// Note: Since this function is currently only used for constant-depth trees which have sequence of
/// hashes as input data, we're using slice of `Hash32` as input type.
pub(crate) fn trace<H: Hasher>(
    data: &[Hash32],
    item_idx: usize,
) -> Result<Vec<Hash32>, MerkleError> {
    if data.len() <= 1 {
        return Ok(Vec::new());
    }

    let sibling = node::<H, Hash32>(split_and_select(data, item_idx, false))?;
    let mut subtree_trace = trace::<H>(
        split_and_select(data, item_idx, true),
        item_idx - merkle_index_offset(data, item_idx),
    )?;

    let mut result = vec![sibling];
    result.append(&mut subtree_trace);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_crypto::hash::Blake2b256;

    #[test]
    fn test_node_empty() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        assert_eq!(root, Hash32::default().to_vec());
        Ok(())
    }

    #[test]
    fn test_node_single_element() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        assert_eq!(root, vec![0, 1]);
        Ok(())
    }

    #[test]
    fn test_node_two_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![10, 11], vec![12, 13]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_three_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![10, 11], vec![12, 13], vec![14, 15]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let hash_10111213 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_10111213, vec![14, 15]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_five_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8, 9]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let hash_0123 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        let hash_012345 =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_0123, vec![4, 5]].concat())?.to_vec();
        let hash_6789 =
            hash::<Blake2b256>(&[b"node".to_vec(), vec![6, 7], vec![8, 9]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[b"node".to_vec(), hash_012345, hash_6789].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }
}
