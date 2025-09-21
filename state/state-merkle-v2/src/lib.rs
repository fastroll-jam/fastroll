//! State Merkle V2
#![allow(dead_code)]
#![allow(unused_imports)]

use fr_common::{MerkleRoot, NodeHash, StateKey};
use std::cmp::Ordering;
// FIXME: Make `fr-state` depend on `fr-state-merkle-v2`
use bitvec::prelude::*;
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

#[derive(Clone)]
struct MerkleNode {
    hash: NodeHash,
    data: Vec<u8>,
}

impl CacheItem for MerkleNode {
    fn into_db_value(self) -> Vec<u8> {
        self.data
    }

    fn from_db_kv(key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self {
            hash: NodeHash::try_from(key).expect("Hash length mismatch"),
            data: val,
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

impl CacheItem for MerklePath {
    fn into_db_value(self) -> Vec<u8> {
        self.0.into_vec()
    }

    fn from_db_kv(_key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self(BitVec::from_vec(val))
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
    leaf_paths: CachedDB<FullMerklePath, MerklePath>,
    root: MerkleRoot,
}

impl MerkleDB {
    fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            nodes: CachedDB::new(core.clone(), cf_name, cache_size),
            leaf_paths: CachedDB::new(core, "merkle_leaf_paths", cache_size), // FIXME
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
        let path = MerklePath(BitVec::from_iter(vec![true, false, true, true]));
        let sibling = path.sibling();
        let sibling_expected = MerklePath(BitVec::from_iter(vec![true, false, true, false]));
        assert_eq!(sibling, sibling_expected);
    }

    #[test]
    fn test_affected_paths_sorting() {
        let paths = HashSet::from_iter(vec![
            MerklePath(BitVec::from_iter(vec![true, false, true, true])), // BitVec(1011)
            MerklePath(BitVec::from_iter(vec![true, false, true, true, true])), // BitVec(10111)
            MerklePath(BitVec::from_iter(vec![true])),                    // BitVec(1)
            MerklePath(BitVec::from_iter(vec![true, false, true, false, true])), // BitVec(10101)
            MerklePath(BitVec::from_iter(vec![true, false])),             // BitVec(10)
        ]);

        let merkle_cache = MerkleCache {
            map: HashMap::new(),
            affected_paths: paths,
        };
        let paths_sorted = merkle_cache.affected_paths_as_sorted_vec();

        let paths_sorted_expected = vec![
            MerklePath(BitVec::from_iter(vec![true, false, true, true, true])), // BitVec(10111)
            MerklePath(BitVec::from_iter(vec![true, false, true, false, true])), // BitVec(10101)
            MerklePath(BitVec::from_iter(vec![true, false, true, true])),       // BitVec(1011)
            MerklePath(BitVec::from_iter(vec![true, false])),                   // BitVec(10)
            MerklePath(BitVec::from_iter(vec![true])),                          // BitVec(1)
        ];
        assert_eq!(paths_sorted, paths_sorted_expected);
    }

    #[test]
    fn test_get_affected_paths() {
        let path = MerklePath(BitVec::from_iter(vec![true, false, true, true])); // BitVec(1011)
        let affected_paths = get_affected_paths(path);
        assert_eq!(affected_paths.len(), 4);
    }
}
