use crate::{
    error::StateMerkleError,
    merkle_db::MerkleDB,
    types::nodes::{ChildType, MerkleNode},
};
use bit_vec::BitVec;
use fr_common::Hash32;
use std::{collections::Bound, ops::RangeBounds};

/// The `bits` function of the GP (MSB-first encoding for each byte)
pub(crate) fn bits_encode_msb(data: &[u8]) -> BitVec {
    let mut bits = BitVec::with_capacity(data.len() * 8);
    for &byte in data {
        for i in 0..8 {
            bits.push(byte & (1 << (7 - i)) != 0);
        }
    }
    bits
}

/// The inverse function of `bits` of the GP.
pub(crate) fn bits_decode_msb(bits: &BitVec) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(bits.len().div_ceil(8));
    let mut current_byte = 0u8;
    for (i, bit) in bits.iter().enumerate() {
        if bit {
            current_byte |= 1 << (7 - (i % 8));
        }
        if i % 8 == 7 {
            bytes.push(current_byte);
            current_byte = 0;
        }
    }
    // push remaining bits as the last byte
    if bits.len() % 8 != 0 {
        bytes.push(current_byte);
    }
    bytes
}

pub(crate) fn bitvec_to_hash32(data: &BitVec) -> Result<Hash32, StateMerkleError> {
    let bytes = bits_decode_msb(data);
    bytes
        .as_slice()
        .try_into()
        .map(Hash32::new)
        .map_err(|_| StateMerkleError::InvalidByteLength(data.len()))
}

pub(crate) fn slice_bitvec<R>(bits: &BitVec, range: R) -> Result<BitVec, StateMerkleError>
where
    R: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        Bound::Included(&start) => start,
        Bound::Excluded(&start) => start + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&end) => end + 1,
        Bound::Excluded(&end) => end,
        Bound::Unbounded => bits.len(),
    };

    if start > bits.len() || end > bits.len() || end < start {
        return Err(StateMerkleError::InvalidBitVecSliceRange);
    }

    Ok(bits
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect())
}

/// Determines whether the new leaf node will be placed as the left or right child in the trie,
/// relative to the sibling node.
pub(crate) fn added_leaf_child_side(
    new_leaf_state_key: Hash32,
    sibling_leaf_partial_state_key: &BitVec,
) -> Result<ChildType, StateMerkleError> {
    let new_leaf_state_key = bits_encode_msb(new_leaf_state_key.as_slice());
    for (new_leaf_bit, sibling_leaf_bit) in new_leaf_state_key
        .iter()
        .zip(sibling_leaf_partial_state_key.iter())
    {
        // The first bit that the new leaf and the sibling leaf diverges
        if new_leaf_bit != sibling_leaf_bit {
            return Ok(ChildType::from_bit(new_leaf_bit));
        }
    }

    Err(StateMerkleError::InvalidMerklePath)
}

pub async fn log_node_data(node: &Option<MerkleNode>, merkle_db: &MerkleDB) {
    match node {
        Some(node) => {
            tracing::trace!(
                ">>> Node: {}",
                node.parse_node_data(merkle_db)
                    .await
                    .expect("Failed to parse node data")
            );
        }
        None => tracing::trace!(">>> None"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_encode_decode_msb() {
        let input = vec![160, 0];
        let encoded = bits_encode_msb(&input);
        let expected = BitVec::from_bytes(&[0b1010_0000, 0]);
        assert_eq!(encoded, expected);

        let decoded = bits_decode_msb(&encoded);
        assert_eq!(input, decoded);
    }
}
