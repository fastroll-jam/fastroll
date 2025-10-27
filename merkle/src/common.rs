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
    #[error("Hashing failed")]
    HashingFailed,
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
fn split_and_select<T: MerkleData>(data: &[T], idx: usize, select_idx_side: bool) -> &[T] {
    let mid = data.len().div_ceil(2);
    if (idx < mid) == select_idx_side {
        &data[..mid]
    } else {
        &data[mid..]
    }
}

/// The `P_I` function which returns 0 for indices in the first half of the data sequence,
/// or the midpoint for those in the second half.
fn merkle_index_offset<T: MerkleData>(data: &[T], idx: usize) -> usize {
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
pub(crate) fn trace<H: Hasher, T: MerkleData>(
    data: &[T],
    item_idx: usize,
) -> Result<Vec<T>, MerkleError> {
    if data.len() <= 1 {
        return Ok(Vec::new());
    }

    let sibling = node::<H, T>(split_and_select(data, item_idx, false))?;
    let mut subtree_trace = trace::<H, T>(
        split_and_select(data, item_idx, true),
        item_idx - merkle_index_offset(data, item_idx),
    )?;

    let mut result = vec![sibling];
    result.append(&mut subtree_trace);
    Ok(result)
}

#[cfg(test)]
mod node_tests {
    use super::*;
    use fr_crypto::hash::Blake2b256;

    const PREFIX: &[u8] = b"node";

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
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_three_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![10, 11], vec![12, 13], vec![14, 15]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let hash_10111213 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![10, 11], vec![12, 13]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[PREFIX.to_vec(), hash_10111213, vec![14, 15]].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }

    #[test]
    fn test_node_five_elements() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8, 9]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let hash_0123 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        let hash_012345 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), hash_0123, vec![4, 5]].concat())?.to_vec();
        let hash_6789 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![6, 7], vec![8, 9]].concat())?.to_vec();
        let expected =
            hash::<Blake2b256>(&[PREFIX.to_vec(), hash_012345, hash_6789].concat())?.to_vec();

        assert_eq!(root, expected);
        Ok(())
    }
}

#[cfg(test)]
mod trace_tests {
    use super::*;
    use fr_crypto::hash::Blake2b256;

    const PREFIX: &[u8] = b"node";

    #[test]
    fn test_trace_empty_data() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[];
        let trace_result = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_result, Vec::<Vec<u8>>::new());
        Ok(())
    }

    #[test]
    fn test_trace_single_item() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0]];
        let trace_result = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_result, Vec::<Vec<u8>>::new());
        Ok(())
    }

    #[test]
    fn test_trace_two_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3]];

        let trace_0 = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_0.len(), 1);
        assert_eq!(trace_0[0], vec![2, 3]);

        let trace_1 = trace::<Blake2b256, Vec<u8>>(data, 1)?;
        assert_eq!(trace_1.len(), 1);
        assert_eq!(trace_1[0], vec![0, 1]);
        Ok(())
    }

    #[test]
    fn test_trace_three_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5]];

        let trace_0 = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_0.len(), 2);
        assert_eq!(trace_0[0], vec![4, 5]);
        assert_eq!(trace_0[1], vec![2, 3]);

        let trace_1 = trace::<Blake2b256, Vec<u8>>(data, 1)?;
        assert_eq!(trace_1.len(), 2);
        assert_eq!(trace_1[0], vec![4, 5]);
        assert_eq!(trace_1[1], vec![0, 1]);

        let trace_2 = trace::<Blake2b256, Vec<u8>>(data, 2)?;
        assert_eq!(trace_2.len(), 1);
        let expected_sibling =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        assert_eq!(trace_2[0], expected_sibling);

        Ok(())
    }

    #[test]
    fn test_trace_four_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7]];

        let trace_0 = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_0.len(), 2);
        let expected_right_subtree =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![4, 5], vec![6, 7]].concat())?.to_vec();
        assert_eq!(trace_0[0], expected_right_subtree);
        assert_eq!(trace_0[1], vec![2, 3]);

        let trace_2 = trace::<Blake2b256, Vec<u8>>(data, 2)?;
        assert_eq!(trace_2.len(), 2);
        let expected_left_subtree =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        assert_eq!(trace_2[0], expected_left_subtree);
        assert_eq!(trace_2[1], vec![6, 7]);
        Ok(())
    }

    #[test]
    fn test_trace_five_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8, 9]];

        let trace_0 = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        assert_eq!(trace_0.len(), 3);
        let expected_right_subtree =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![6, 7], vec![8, 9]].concat())?.to_vec();
        assert_eq!(trace_0[0], expected_right_subtree);
        assert_eq!(trace_0[1], vec![4, 5]);
        assert_eq!(trace_0[2], vec![2, 3]);

        let trace_4 = trace::<Blake2b256, Vec<u8>>(data, 4)?;
        assert_eq!(trace_4.len(), 2);
        let hash_0123 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), vec![0, 1], vec![2, 3]].concat())?.to_vec();
        let expected_left_subtree =
            hash::<Blake2b256>(&[PREFIX.to_vec(), hash_0123, vec![4, 5]].concat())?.to_vec();
        assert_eq!(trace_4[0], expected_left_subtree);
        assert_eq!(trace_4[1], vec![6, 7]);
        Ok(())
    }

    #[test]
    fn test_trace_verify_two_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let trace_0 = trace::<Blake2b256, Vec<u8>>(data, 0)?;
        let leaf = &data[0];

        let reconstructed_root =
            hash::<Blake2b256>(&[PREFIX.to_vec(), leaf.clone(), trace_0[0].clone()].concat())?
                .to_vec();

        assert_eq!(reconstructed_root, root);
        Ok(())
    }

    #[test]
    fn test_trace_verify_four_items() -> Result<(), MerkleError> {
        let data: &[Vec<u8>] = &[vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7]];
        let root = node::<Blake2b256, Vec<u8>>(data)?;

        let trace_2 = trace::<Blake2b256, Vec<u8>>(data, 2)?;
        let leaf = &data[2];

        let level1 =
            hash::<Blake2b256>(&[PREFIX.to_vec(), leaf.clone(), trace_2[1].clone()].concat())?
                .to_vec();

        let reconstructed_root =
            hash::<Blake2b256>(&[PREFIX.to_vec(), trace_2[0].clone(), level1].concat())?.to_vec();

        assert_eq!(reconstructed_root, root);
        Ok(())
    }

    #[test]
    fn test_trace_hash_input_three_items() -> Result<(), MerkleError> {
        // Test trace function with Hash32 type inputs
        let hash1 = hash::<Blake2b256>(b"012")?;
        let hash2 = hash::<Blake2b256>(b"345")?;
        let hash3 = hash::<Blake2b256>(b"678")?;

        let data: &[Hash32] = &[hash1.clone(), hash2.clone(), hash3.clone()];

        let trace_0 = trace::<Blake2b256, Hash32>(data, 0)?;
        assert_eq!(trace_0.len(), 2);
        assert_eq!(trace_0[0], hash3);
        assert_eq!(trace_0[1], hash2);

        let trace_1 = trace::<Blake2b256, Hash32>(data, 1)?;
        assert_eq!(trace_1.len(), 2);
        assert_eq!(trace_1[0], hash3);
        assert_eq!(trace_1[1], hash1);

        let trace_2 = trace::<Blake2b256, Hash32>(data, 2)?;
        assert_eq!(trace_2.len(), 1);
        let sibling_expected =
            hash::<Blake2b256>(&[PREFIX, hash1.as_slice(), hash2.as_slice()].concat())?;
        assert_eq!(trace_2[0], sibling_expected);

        Ok(())
    }
}
