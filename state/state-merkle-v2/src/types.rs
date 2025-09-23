use crate::utils::{bits_decode_msb, bits_encode_msb, bitvec_to_hash, slice_bitvec};
use bitvec::{bitvec, order::Msb0, prelude::BitVec};
use fr_codec::prelude::*;
use fr_common::{ByteEncodable, Hash32, NodeHash};
use fr_crypto::error::CryptoError;
use fr_db::core::cached_db::{CacheItem, CacheItemCodecError, CachedDBError};
use thiserror::Error;

/// Merkle node data size in bits.
pub const NODE_SIZE_BITS: usize = 512;

#[derive(Debug, Error)]
pub enum StateMerkleError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("CachedDBError: {0}")]
    CachedDBError(#[from] CachedDBError),
    #[error("Invalid node type with hash")]
    InvalidNodeType,
    #[error("Invalid byte length")]
    InvalidByteLength(usize),
    #[error("Invalid BitVec slice range")]
    InvalidBitVecSliceRange,
    #[error("Invalid node data length")]
    InvalidNodeDataLength(usize),
    #[error("Merkle path unknown for state key: {0}")]
    MerklePathUnknownForStateKey(String),
    #[error("Merkle trie is not initialized yet")]
    MerkleTrieNotInitialized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LeafNodeData {
    Embedded(Vec<u8>),
    Regular(Hash32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeafNode {
    pub(crate) state_key_bv: BitVec<u8, Msb0>,
    data: LeafNodeData,
}

impl LeafNode {
    pub(crate) fn new(state_key_bv: BitVec<u8, Msb0>, data: LeafNodeData) -> Self {
        Self { state_key_bv, data }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, StateMerkleError> {
        let mut node = bitvec![u8, Msb0; 1]; // Indicator for leaf node
        match &self.data {
            LeafNodeData::Embedded(state_val) => {
                node.push(false); // Indicator for embedded leaf
                let lengths_bits = bits_encode_msb(&state_val.len().encode_fixed(1)?); // 8 bits

                node.extend(slice_bitvec(&lengths_bits, 2..)?);
                node.extend(self.state_key_bv.clone());
                node.extend(bits_encode_msb(state_val));

                while node.len() < NODE_SIZE_BITS {
                    node.push(false); // zero padding for the remaining bits
                }
            }
            LeafNodeData::Regular(state_hash) => {
                node.push(true); // Indicator for regular leaf
                node.extend(bitvec![u8, Msb0; 0, 0, 0, 0, 0, 0]); // zero padding
                node.extend(self.state_key_bv.clone());
                node.extend(bits_encode_msb(state_hash.as_slice()));
            }
        }

        Ok(bits_decode_msb(node))
    }

    pub(crate) fn decode(node_data_bv: &BitVec<u8, Msb0>) -> Result<Self, StateMerkleError> {
        // check node data length
        let len = node_data_bv.len();
        if len != NODE_SIZE_BITS {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let first_bit = node_data_bv.get(0).map(|b| *b);
        let second_bit = node_data_bv.get(1).map(|b| *b);

        match (first_bit, second_bit) {
            (Some(true), Some(true)) => {
                // Regular Leaf
                let val_hash_bv = slice_bitvec(node_data_bv, 256..)?.to_bitvec();
                let state_key_bv = slice_bitvec(node_data_bv, 8..256)?.to_bitvec();
                Ok(Self {
                    state_key_bv,
                    data: LeafNodeData::Regular(bitvec_to_hash(val_hash_bv)?),
                })
            }
            (Some(true), Some(false)) => {
                // Embedded Leaf
                // Pad the leading 2 bits with zeros (which were dropped while encoding)
                let mut length_bits_padded = bitvec![u8, Msb0; 0, 0];
                length_bits_padded.extend(slice_bitvec(node_data_bv, 2..8)?);
                let val_len_decoded =
                    u8::decode_fixed(&mut bits_decode_msb(length_bits_padded).as_slice(), 1)?;
                let val_len_in_bits = (val_len_decoded as usize) * 8;
                let val_end_bit = 256 + val_len_in_bits;
                let val =
                    bits_decode_msb(slice_bitvec(node_data_bv, 256..val_end_bit)?.to_bitvec());
                let state_key_bv = slice_bitvec(node_data_bv, 8..256)?.to_bitvec();

                Ok(Self {
                    state_key_bv,
                    data: LeafNodeData::Embedded(val),
                })
            }
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BranchNode {
    /// 255-bit left child node hash value, with the first bit dropped.
    left_lossy: BitVec<u8, Msb0>,
    /// The right child node hash value.
    right: BitVec<u8, Msb0>,
}

impl BranchNode {
    pub(crate) fn new(left: &NodeHash, right: &NodeHash) -> Self {
        let left_bv = bits_encode_msb(left.as_slice());
        let right_bv = bits_encode_msb(right.as_slice());
        Self {
            left_lossy: slice_bitvec(&left_bv, 1..)
                .expect("Has 256 bits")
                .to_bitvec(),
            right: right_bv,
        }
    }

    pub(crate) fn has_single_child(&self) -> bool {
        let left_is_zero = !self.left_lossy.any();
        let right_is_zero = !self.right.any();
        left_is_zero ^ right_is_zero
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, StateMerkleError> {
        let mut node_data = bitvec![u8, Msb0; 0]; // Indicator for branch node
        node_data.extend(self.left_lossy.clone());
        node_data.extend(self.right.clone());
        Ok(bits_decode_msb(node_data))
    }

    pub(crate) fn decode(node_data_bv: &BitVec<u8, Msb0>) -> Result<Self, StateMerkleError> {
        // check node data length
        let len = node_data_bv.len();
        if len != NODE_SIZE_BITS {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let first_bit = node_data_bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if *first_bit {
            return Err(StateMerkleError::InvalidNodeType);
        }

        let left_lossy = slice_bitvec(node_data_bv, 1..=255)?.to_bitvec();
        let right = slice_bitvec(node_data_bv, 256..)?.to_bitvec();

        Ok(Self { left_lossy, right })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MerkleNode {
    Leaf(LeafNode),
    Branch(BranchNode),
}

// TODO: Error propagation
impl CacheItem for MerkleNode {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        match self {
            Self::Leaf(leaf) => Ok(leaf.encode().expect("Failed to encode Leaf MerkleNode")),
            Self::Branch(branch) => {
                Ok(branch.encode().expect("Failed to encode Branch MerkleNode"))
            }
        }
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Result<Self, CacheItemCodecError>
    where
        Self: Sized,
    {
        let node_data_bv = bits_encode_msb(val.as_slice());
        let first_bit = node_data_bv.get(0).map(|b| *b);
        let second_bit = node_data_bv.get(1).map(|b| *b);

        match (first_bit, second_bit) {
            (Some(true), _) => {
                // Leaf Node
                Ok(Self::Leaf(
                    LeafNode::decode(&node_data_bv).expect("Failed to decode Leaf node"),
                ))
            }
            (Some(false), _) => {
                // Branch Node
                Ok(Self::Branch(
                    BranchNode::decode(&node_data_bv).expect("Failed to decode Branch node"),
                ))
            }
            _ => {
                panic!("Invalid node data")
            }
        }
    }
}

/// A bit vector representing the path from the merkle root to a node.
///
/// For leaf nodes, this path may be shorter than the full state key.
/// This happens since the trie doesn't create intermediate nodes for unique paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MerklePath(pub(crate) BitVec<u8, Msb0>);

impl AsRef<[u8]> for MerklePath {
    fn as_ref(&self) -> &[u8] {
        self.0.as_raw_slice()
    }
}

impl CacheItem for MerklePath {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        Ok(bits_decode_msb(self.0))
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Result<Self, CacheItemCodecError>
    where
        Self: Sized,
    {
        Ok(Self(bits_encode_msb(val.as_slice())))
    }
}

impl MerklePath {
    pub(crate) fn sibling(&self) -> Option<Self> {
        if self.0.is_empty() {
            return None;
        }
        let mut sibling = self.clone();
        let last_bit = sibling
            .0
            .pop()
            .expect("MerklePath BitVec should not be empty");
        sibling.0.push(!last_bit);
        Some(sibling)
    }

    pub(crate) fn left_child(&self) -> Option<Self> {
        if self.0.len() >= NODE_SIZE_BITS {
            return None;
        }
        let mut left_child = self.clone();
        left_child.0.push(false);
        Some(left_child)
    }

    pub(crate) fn right_child(&self) -> Option<Self> {
        if self.0.len() >= NODE_SIZE_BITS {
            return None;
        }
        let mut right_child = self.clone();
        right_child.0.push(true);
        Some(right_child)
    }

    /// Returns the given merkle path and all its parent paths.
    /// For example, an input of `1011` will return `[1011, 101, 10, 1]`.
    pub(crate) fn all_paths_to_root(&self) -> Vec<MerklePath> {
        let mut merkle_path = self.clone();
        let mut result = Vec::with_capacity(merkle_path.0.len());
        while !merkle_path.0.is_empty() {
            result.push(merkle_path.clone());
            merkle_path.0.pop();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_common::StateHash;

    #[test]
    fn test_merkle_path_sibling() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let sibling = path.sibling();
        let sibling_expected = Some(MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0]));
        assert_eq!(sibling, sibling_expected);
    }

    #[test]
    fn test_merkle_path_left_child() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let left_child = path.left_child();
        let left_child_expected = Some(MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 0]));
        assert_eq!(left_child, left_child_expected);
    }

    #[test]
    fn test_merkle_path_right_child() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let right_child = path.right_child();
        let right_child_expected = Some(MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]));
        assert_eq!(right_child, right_child_expected);
    }

    #[test]
    fn test_all_paths_to_root() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let all_paths_to_root = path.all_paths_to_root();
        assert_eq!(all_paths_to_root.len(), 4);
        assert!(all_paths_to_root.contains(&MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1])));
        assert!(all_paths_to_root.contains(&MerklePath(bitvec![u8, Msb0; 1, 0, 1])));
        assert!(all_paths_to_root.contains(&MerklePath(bitvec![u8, Msb0; 1, 0])));
        assert!(all_paths_to_root.contains(&MerklePath(bitvec![u8, Msb0; 1])));
    }

    #[test]
    fn test_branch_encode_decode() {
        let left_bv = bits_encode_msb(&[0xAA; 32]);
        let right_bv = bits_encode_msb(&[0xBB; 32]);

        let branch_node = BranchNode {
            left_lossy: slice_bitvec(&left_bv, 1..).unwrap().to_bitvec(),
            right: right_bv,
        };

        let encoded = branch_node.encode().unwrap();
        assert_eq!(encoded.len(), NODE_SIZE_BITS / 8);

        let encoded_bv = bits_encode_msb(encoded.as_slice());
        let decoded = BranchNode::decode(&encoded_bv).unwrap();

        assert_eq!(branch_node, decoded);
    }

    #[test]
    fn test_embedded_leaf_encode_decode() {
        let state_key_bv = bits_encode_msb(&[0xAA; 31]);
        let state_val = vec![0xFFu8; 32];

        let leaf_node = LeafNode {
            state_key_bv,
            data: LeafNodeData::Embedded(state_val),
        };

        let encoded = leaf_node.encode().unwrap();
        assert_eq!(encoded.len(), NODE_SIZE_BITS / 8);

        let encoded_bv = bits_encode_msb(encoded.as_slice());
        let decoded = LeafNode::decode(&encoded_bv).unwrap();

        assert_eq!(leaf_node, decoded);
    }

    #[test]
    fn test_regular_leaf_encode_decode() {
        let state_key_bv = bits_encode_msb(&[0xAA; 31]);
        let state_hash = StateHash::from_slice(&[0xBB; 32]).unwrap();

        let leaf_node = LeafNode {
            state_key_bv,
            data: LeafNodeData::Regular(state_hash),
        };

        let encoded = leaf_node.encode().unwrap();
        assert_eq!(encoded.len(), NODE_SIZE_BITS / 8);

        let encoded_bv = bits_encode_msb(encoded.as_slice());
        let decoded = LeafNode::decode(&encoded_bv).unwrap();

        assert_eq!(leaf_node, decoded);
    }
}
