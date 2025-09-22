//! State Merkle V2
#![allow(dead_code)]
#![allow(unused_imports)]

mod utils;

use fr_codec::prelude::*;
use fr_common::{Hash32, MerkleRoot, NodeHash, StateKey};
use std::cmp::Ordering;
// FIXME: Make `fr-state` depend on `fr-state-merkle-v2`
use crate::utils::{bits_decode_msb, bits_encode_msb, bitvec_to_hash, slice_bitvec};
use bitvec::{macros::internal::funty::Fundamental, prelude::*};
use fr_db::core::{
    cached_db::{CacheItem, CachedDB},
    core_db::CoreDB,
};
use fr_state::cache::{CacheEntry, CacheEntryStatus, StateMut};
use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    sync::Arc,
};
use thiserror::Error;

/// Merkle node data size in bits.
pub const NODE_SIZE_BITS: usize = 512;

#[derive(Debug, Error)]
enum StateMerkleError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("Invalid node type with hash")]
    InvalidNodeType,
    #[error("Invalid byte length")]
    InvalidByteLength(usize),
    #[error("Invalid BitVec slice range")]
    InvalidBitVecSliceRange,
    #[error("Invalid node data length")]
    InvalidNodeDataLength(usize),
}

#[derive(Clone, Debug)]
enum LeafNodeData {
    Embedded(Vec<u8>),
    Regular(Hash32),
}

#[derive(Clone, Debug)]
struct LeafNode {
    state_key_bv: BitVec<u8, Msb0>,
    data: LeafNodeData,
}

impl LeafNode {
    fn encode(&self) -> Result<Vec<u8>, StateMerkleError> {
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
                node.extend(bits_encode_msb(state_hash.as_slice()));
            }
        }

        Ok(bits_decode_msb(node))
    }

    fn decode(node_data_bv: BitVec<u8, Msb0>) -> Result<Self, StateMerkleError> {
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
                let val_hash_bv = slice_bitvec(&node_data_bv, 256..)?.to_bitvec();
                let state_key_bv = slice_bitvec(&node_data_bv, 8..256)?.to_bitvec();
                Ok(Self {
                    state_key_bv,
                    data: LeafNodeData::Regular(bitvec_to_hash(val_hash_bv)?),
                })
            }
            (Some(true), Some(false)) => {
                // Embedded Leaf
                // Pad the leading 2 bits with zeros (which were dropped while encoding)
                let mut length_bits_padded = bitvec![u8, Msb0; 0, 0];
                length_bits_padded.extend(slice_bitvec(&node_data_bv, 2..8)?);
                let val_len_decoded =
                    u8::decode_fixed(&mut bits_decode_msb(length_bits_padded).as_slice(), 1)?;
                let val_len_in_bits = (val_len_decoded as usize) * 8;
                let val_end_bit = 256 + val_len_in_bits;
                let val =
                    bits_decode_msb(slice_bitvec(&node_data_bv, 256..val_end_bit)?.to_bitvec());
                let state_key_bv = slice_bitvec(&node_data_bv, 8..256)?.to_bitvec();

                Ok(Self {
                    state_key_bv,
                    data: LeafNodeData::Embedded(val),
                })
            }
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }
}

#[derive(Clone, Debug)]
struct BranchNode {
    left_lossy: BitVec<u8, Msb0>,
    right: BitVec<u8, Msb0>,
}

impl BranchNode {
    fn encode(&self) -> Result<Vec<u8>, StateMerkleError> {
        let mut node_data = bitvec![u8, Msb0; 0]; // Indicator for branch node
        let left_255_bv = slice_bitvec(&self.left_lossy, 1..)?.to_bitvec();
        node_data.extend(left_255_bv);
        node_data.extend(self.right.clone());
        Ok(bits_decode_msb(node_data))
    }

    fn decode(node_data_bv: BitVec<u8, Msb0>) -> Result<Self, StateMerkleError> {
        // check node data length
        let len = node_data_bv.len();
        if len != NODE_SIZE_BITS {
            return Err(StateMerkleError::InvalidNodeDataLength(len));
        }

        let first_bit = node_data_bv.get(0).unwrap();

        // ensure the node data represents a branch node
        if first_bit.as_bool() {
            return Err(StateMerkleError::InvalidNodeType);
        }

        let mut left_lossy = slice_bitvec(&node_data_bv, 1..=255)?.to_bitvec();
        left_lossy.insert(0, false); // Push an arbitrary bit (0)
        let right = slice_bitvec(&node_data_bv, 256..)?.to_bitvec();

        Ok(Self { left_lossy, right })
    }
}

#[derive(Clone, Debug)]
enum MerkleNode {
    Leaf(LeafNode),
    Branch(BranchNode),
}

impl CacheItem for MerkleNode {
    fn into_db_value(self) -> Vec<u8> {
        match self {
            Self::Leaf(leaf) => leaf.encode().expect("Failed to encode Leaf MerkleNode"),
            Self::Branch(branch) => branch.encode().expect("Failed to encode Branch MerkleNode"),
        }
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        let node_data_bv = bits_encode_msb(val.as_slice());
        let first_bit = node_data_bv.get(0).map(|b| *b);
        let second_bit = node_data_bv.get(1).map(|b| *b);

        match (first_bit, second_bit) {
            (Some(true), _) => {
                // Leaf Node
                Self::Leaf(LeafNode::decode(node_data_bv).expect("Failed to decode Leaf node"))
            }
            (Some(false), _) => {
                // Branch Node
                Self::Branch(
                    BranchNode::decode(node_data_bv).expect("Failed to decode Branch node"),
                )
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
struct MerklePath(BitVec<u8, Msb0>);

impl AsRef<[u8]> for MerklePath {
    fn as_ref(&self) -> &[u8] {
        self.0.as_raw_slice()
    }
}

/// A bit vector representing the path from the merkle root to a node.
///
/// Unlike `MerklePath`, this exactly matches with the bit vector representation of state keys
/// for leaf nodes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FullMerklePath(BitVec<u8, Msb0>);

impl AsRef<[u8]> for FullMerklePath {
    fn as_ref(&self) -> &[u8] {
        self.0.as_raw_slice()
    }
}

impl MerklePath {
    fn sibling(&self) -> Self {
        let mut sibling = self.clone();
        let last_bit = sibling.0.pop().unwrap();
        sibling.0.push(!last_bit);
        sibling
    }
}

type NodeWithPath = (MerklePath, MerkleNode);

struct MerkleDB {
    nodes: CachedDB<MerklePath, MerkleNode>,
    leaf_nodes: CachedDB<FullMerklePath, MerkleNode>,
    root: MerkleRoot,
}

impl MerkleDB {
    fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            nodes: CachedDB::new(core.clone(), cf_name, cache_size),
            leaf_nodes: CachedDB::new(core.clone(), "leaf_nodes", cache_size), // FIXME cf name
            root: MerkleRoot::default(),
        }
    }
}

struct MerkleCache {
    map: HashMap<MerklePath, MerkleNode>,
    affected_paths: HashSet<MerklePath>,
}

impl MerkleCache {
    fn affected_paths_as_sorted_vec(self) -> Vec<MerklePath> {
        let mut affected_paths_vec = self.affected_paths.into_iter().collect::<Vec<_>>();
        affected_paths_vec.sort_by(|a, b| {
            // First, sort by the path length (descending)
            match b.0.len().cmp(&a.0.len()) {
                Ordering::Equal => {
                    // For paths with the same length, sort by numerical value (descending)
                    for i in (0..a.0.len()).rev() {
                        match b.0.get(i).unwrap().cmp(&a.0.get(i).unwrap()) {
                            Ordering::Equal => continue,
                            other => return other,
                        }
                    }
                    // The exactly same path
                    Ordering::Equal
                }
                other => other,
            }
        });
        affected_paths_vec
    }
}

/// Returns the given merkle path and all its parent paths.
/// For example, an input of `1011` will return `[1011, 101, 10, 1]`.
fn get_affected_paths(merkle_path: MerklePath) -> Vec<MerklePath> {
    let mut merkle_path = merkle_path.clone();
    let mut result = Vec::with_capacity(merkle_path.0.len());
    while !merkle_path.0.is_empty() {
        result.push(merkle_path.clone());
        merkle_path.0.pop();
    }
    result
}

fn dirty_state_cache_entry_to_node_with_path(
    dirty_entries: &[(StateKey, CacheEntry)],
) -> NodeWithPath {
    for (_state_key, entry) in dirty_entries {
        if let CacheEntryStatus::Dirty(state_mut) = &entry.status {
            match state_mut {
                StateMut::Add => {}
                StateMut::Update => {}
                StateMut::Remove => {}
            }
        }
    }

    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_path_sibling() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let sibling = path.sibling();
        let sibling_expected = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0]);
        assert_eq!(sibling, sibling_expected);
    }

    #[test]
    fn test_affected_paths_sorting() {
        let paths = HashSet::from_iter(vec![
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0]),
        ]);

        let merkle_cache = MerkleCache {
            map: HashMap::new(),
            affected_paths: paths,
        };
        let paths_sorted = merkle_cache.affected_paths_as_sorted_vec();

        let paths_sorted_expected = vec![
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0]),
            MerklePath(bitvec![u8, Msb0; 1]),
        ];
        assert_eq!(paths_sorted, paths_sorted_expected);
    }

    #[test]
    fn test_get_affected_paths() {
        let path = MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]);
        let affected_paths = get_affected_paths(path);
        assert_eq!(affected_paths.len(), 4);
    }

    #[test]
    fn test_branch_encode() {}
}
