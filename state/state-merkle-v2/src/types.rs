use crate::utils::{bits_decode_msb, bits_encode_msb, bitvec_to_hash, slice_bitvec};
use bitvec::prelude::*;
use fr_codec::prelude::*;
use fr_common::{ByteEncodable, CommonTypeError, Hash32, NodeHash};
use fr_crypto::{error::CryptoError, hash, Blake2b256};
use fr_db::core::{
    cached_db::{CacheItem, CacheItemCodecError, CachedDBError, DBKey},
    core_db::CoreDBError,
};
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt::{Display, Formatter},
};
use thiserror::Error;
use tokio::task::JoinError;

/// Merkle node data size in bits.
pub const NODE_SIZE_BITS: usize = 512;

#[derive(Debug, Error)]
pub enum StateMerkleError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
    #[error("CachedDBError: {0}")]
    CachedDBError(#[from] CachedDBError),
    #[error("CacheItemCodecError: {0}")]
    CacheItemCodecError(#[from] CacheItemCodecError),
    #[error("tokio JoinError: {0}")]
    JoinError(#[from] JoinError),
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
    #[error("A node that corresponds to the given merkle path is not found either from MerkleDB or MerkleChangeSet"
    )]
    InvalidAffectedMerklePath,
    #[error("Merkle branch at path {0} is missing or malformed")]
    InvalidBranchStructure(String),
    #[error("Merkle root should be always affected unless the merkle trie is unchanged")]
    MissingAffectedMerkleRoot,
    #[error("Merkle root should not be removed")]
    RemovingMerkleRoot,
    #[error("Affected leaf node is not found from the MerkleChangeSet")]
    AffectedLeafNotFoundFromMerkleChangeSet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafNodeData {
    Embedded(Vec<u8>),
    Regular(Hash32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafNode {
    pub state_key_bv: BitVec<u8, Msb0>,
    pub data: LeafNodeData,
}

impl Display for LeafNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let node = MerkleNode::Leaf(self.clone());
        let hash = &hex::encode(node.hash().unwrap().0)[0..6];
        write!(f, "Leaf({hash})")
    }
}

impl LeafNode {
    pub fn new(state_key_bv: BitVec<u8, Msb0>, data: LeafNodeData) -> Self {
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
pub struct BranchNode {
    /// 255-bit left child node hash value, with the first bit dropped.
    pub(crate) left_lossy: BitVec<u8, Msb0>,
    /// The right child node hash value.
    pub(crate) right: BitVec<u8, Msb0>,
}

impl Display for BranchNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Left child recovered with '0' as the first bit
        let mut left0_bv = bitvec![u8, Msb0; 0];
        left0_bv.extend(self.left_lossy.clone());
        // Left child recovered with '1' as the first bit
        let mut left1_bv = bitvec![u8, Msb0; 1];
        left1_bv.extend(self.left_lossy.clone());
        let left0 = &hex::encode(bits_decode_msb(left0_bv))[0..6];
        let left1 = &hex::encode(bits_decode_msb(left1_bv))[0..6];

        let right = &hex::encode(bits_decode_msb(self.right.clone()).as_slice())[0..6];
        let branch = MerkleNode::Branch(self.clone());
        let branch_hash = branch.hash().unwrap();
        let hash = &hex::encode(branch_hash.0)[0..6];
        write!(
            f,
            "Branch(hash={hash}, left0={left0}, left1={left1}, right={right})"
        )
    }
}

impl BranchNode {
    pub fn new(left: &NodeHash, right: &NodeHash) -> Self {
        let left_bv = bits_encode_msb(left.as_slice());
        let right_bv = bits_encode_msb(right.as_slice());
        Self {
            left_lossy: slice_bitvec(&left_bv, 1..)
                .expect("Has 256 bits")
                .to_bitvec(),
            right: right_bv,
        }
    }

    pub fn update_left(&mut self, left: &NodeHash) {
        let left_bv = bits_encode_msb(left.as_slice());
        self.left_lossy = slice_bitvec(&left_bv, 1..)
            .expect("Has 256 bits")
            .to_bitvec();
    }

    pub fn update_right(&mut self, right: &NodeHash) {
        self.right = bits_encode_msb(right.as_slice());
    }

    pub fn has_single_child(&self) -> bool {
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
pub enum MerkleNode {
    Leaf(LeafNode),
    Branch(BranchNode),
}

impl Display for MerkleNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Leaf(leaf) => write!(f, "{}", leaf),
            Self::Branch(branch) => write!(f, "{}", branch),
        }
    }
}

impl CacheItem for MerkleNode {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        match self {
            Self::Leaf(leaf) => Ok(leaf
                .encode()
                .map_err(|e| CacheItemCodecError::InvalidCacheItemValue(e.to_string()))?),
            Self::Branch(branch) => Ok(branch
                .encode()
                .map_err(|e| CacheItemCodecError::InvalidCacheItemValue(e.to_string()))?),
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
                Ok(Self::Leaf(LeafNode::decode(&node_data_bv).map_err(
                    |e| CacheItemCodecError::InvalidCacheItemValue(e.to_string()),
                )?))
            }
            (Some(false), _) => {
                // Branch Node
                Ok(Self::Branch(BranchNode::decode(&node_data_bv).map_err(
                    |e| CacheItemCodecError::InvalidCacheItemValue(e.to_string()),
                )?))
            }
            _ => Err(CacheItemCodecError::InvalidCacheItemValue(
                "Invalid node data".to_string(),
            )),
        }
    }
}

impl MerkleNode {
    pub fn is_branch(&self) -> bool {
        matches!(self, Self::Branch(_))
    }

    #[allow(dead_code)]
    pub(crate) fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }

    fn encode(&self) -> Result<Vec<u8>, StateMerkleError> {
        match self {
            Self::Branch(branch) => branch.encode(),
            Self::Leaf(leaf) => leaf.encode(),
        }
    }

    pub fn hash(&self) -> Result<NodeHash, StateMerkleError> {
        Ok(hash::<Blake2b256>(self.encode()?.as_slice())?)
    }
}

/// A bit vector representing the path from the merkle root to a node.
///
/// For leaf nodes, this path may be shorter than the full state key.
/// This happens since the trie doesn't create intermediate nodes for unique paths.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MerklePath(pub BitVec<u8, Msb0>);

impl PartialOrd for MerklePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MerklePath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.len().cmp(&other.0.len()).then(self.0.cmp(&other.0))
    }
}

// MerklePath lengths and prefixes should be preserved; we construct String keys here
// for correct serialization of `MerklePath` as CacheDB keys.
impl DBKey for MerklePath {
    fn as_db_key(&'_ self) -> Cow<'_, [u8]> {
        let key_string: String = self.0.iter().map(|b| if *b { '1' } else { '0' }).collect();
        Cow::Owned(key_string.into_bytes())
    }

    fn from_db_key(key: &[u8]) -> Result<Self, CachedDBError> {
        let string_key =
            String::from_utf8(key.to_vec()).map_err(|_| CachedDBError::InvalidCachedDBKey)?;
        let mut bv = BitVec::<u8, Msb0>::new();
        for char in string_key.chars() {
            match char {
                '1' => bv.push(true),
                '0' => bv.push(false),
                _ => return Err(CachedDBError::InvalidCachedDBKey),
            }
        }

        Ok(Self(bv))
    }
}

impl CacheItem for MerklePath {
    fn into_db_value(self) -> Result<Vec<u8>, CacheItemCodecError> {
        let val_string: String = self
            .0
            .iter()
            .by_vals()
            .map(|b| if b { '1' } else { '0' })
            .collect();
        Ok(val_string.into_bytes())
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Result<Self, CacheItemCodecError>
    where
        Self: Sized,
    {
        let string_val = String::from_utf8(val)
            .map_err(|e| CacheItemCodecError::InvalidCacheItemValue(e.to_string()))?;
        let mut bv = BitVec::<u8, Msb0>::new();
        for char in string_val.chars() {
            match char {
                '1' => bv.push(true),
                '0' => bv.push(false),
                other => {
                    return Err(CacheItemCodecError::InvalidCacheItemValue(format!(
                        "Invalid character for bits: {other}"
                    )))
                }
            }
        }

        Ok(Self(bv))
    }
}

impl MerklePath {
    pub fn root() -> Self {
        Self(BitVec::new())
    }

    pub fn sibling(&self) -> Option<Self> {
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

    pub fn left_child(&self) -> Option<Self> {
        if self.0.len() >= NODE_SIZE_BITS {
            return None;
        }
        let mut left_child = self.clone();
        left_child.0.push(false);
        Some(left_child)
    }

    pub fn right_child(&self) -> Option<Self> {
        if self.0.len() >= NODE_SIZE_BITS {
            return None;
        }
        let mut right_child = self.clone();
        right_child.0.push(true);
        Some(right_child)
    }

    /// Returns the given merkle path and all its parent paths.
    /// For example, an input of `1011` will return `[1011, 101, 10, 1, root]`.
    pub fn all_paths_to_root(&self) -> Vec<MerklePath> {
        let mut merkle_path = self.clone();
        let mut result = Vec::with_capacity(merkle_path.0.len() + 1);
        while !merkle_path.0.is_empty() {
            result.push(merkle_path.clone());
            merkle_path.0.pop();
        }
        // Empty MerklePath represents the root node
        result.push(Self::root());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path;
    use fr_common::StateHash;

    #[test]
    fn test_merkle_path_sibling() {
        let path = merkle_path![1, 0, 1, 1];
        let sibling = path.sibling();
        let sibling_expected = Some(merkle_path![1, 0, 1, 0]);
        assert_eq!(sibling, sibling_expected);
    }

    #[test]
    fn test_merkle_path_left_child() {
        let path = merkle_path![1, 0, 1, 1];
        let left_child = path.left_child();
        let left_child_expected = Some(merkle_path![1, 0, 1, 1, 0]);
        assert_eq!(left_child, left_child_expected);
    }

    #[test]
    fn test_merkle_path_right_child() {
        let path = merkle_path![1, 0, 1, 1];
        let right_child = path.right_child();
        let right_child_expected = Some(merkle_path![1, 0, 1, 1, 1]);
        assert_eq!(right_child, right_child_expected);
    }

    #[test]
    fn test_all_paths_to_root() {
        let path = merkle_path![1, 0, 1, 1];
        let all_paths_to_root = path.all_paths_to_root();
        assert_eq!(all_paths_to_root.len(), 5);
        assert!(all_paths_to_root.contains(&merkle_path![1, 0, 1, 1]));
        assert!(all_paths_to_root.contains(&merkle_path![1, 0, 1]));
        assert!(all_paths_to_root.contains(&merkle_path![1, 0]));
        assert!(all_paths_to_root.contains(&merkle_path![1]));
        assert!(all_paths_to_root.contains(&merkle_path![]));
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
