//! State Merkle V2
#![allow(dead_code)]
#![allow(unused_imports)]

use bit_vec::BitVec;
use fr_common::{NodeHash, StateKey};
use std::cmp::Ordering;
// FIXME: Make `fr-state` depend on `fr-state-merkle-v2`
use fr_state::cache::CacheEntry;
use std::{collections::HashMap, ops::Deref};

struct MerkleNode {
    hash: NodeHash,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MerklePath(BitVec);

impl MerklePath {
    fn sibling(&self) -> Self {
        let mut sibling = self.clone();
        let last_bit = sibling.0.pop().unwrap();
        sibling.0.push(!last_bit);
        sibling
    }
}

type NodeWithPath = (MerklePath, MerkleNode);

struct MerkleCache {
    map: HashMap<MerklePath, MerkleNode>,
    affected_paths: Vec<MerklePath>,
}

impl MerkleCache {
    fn sort_affected_paths(&mut self) {
        self.affected_paths.sort_by(|a, b| {
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
        })
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
    _dirty_entries: &[(StateKey, CacheEntry)],
) -> NodeWithPath {
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
        let paths = vec![
            MerklePath(BitVec::from_iter(vec![true, false, true, true])), // BitVec(1011)
            MerklePath(BitVec::from_iter(vec![true, false, true, true, true])), // BitVec(10111)
            MerklePath(BitVec::from_iter(vec![true])),                    // BitVec(1)
            MerklePath(BitVec::from_iter(vec![true, false, true, false, true])), // BitVec(10101)
            MerklePath(BitVec::from_iter(vec![true, false])),             // BitVec(10)
        ];

        let mut merkle_cache = MerkleCache {
            map: HashMap::new(),
            affected_paths: paths,
        };
        merkle_cache.sort_affected_paths();

        let paths_sorted = vec![
            MerklePath(BitVec::from_iter(vec![true, false, true, true, true])), // BitVec(10111)
            MerklePath(BitVec::from_iter(vec![true, false, true, false, true])), // BitVec(10101)
            MerklePath(BitVec::from_iter(vec![true, false, true, true])),       // BitVec(1011)
            MerklePath(BitVec::from_iter(vec![true, false])),                   // BitVec(10)
            MerklePath(BitVec::from_iter(vec![true])),                          // BitVec(1)
        ];
        assert_eq!(paths_sorted, merkle_cache.affected_paths);
    }

    #[test]
    fn test_get_affected_paths() {
        let path = MerklePath(BitVec::from_iter(vec![true, false, true, true])); // BitVec(1011)
        let affected_paths = get_affected_paths(path);
        assert_eq!(affected_paths.len(), 4);
    }
}
