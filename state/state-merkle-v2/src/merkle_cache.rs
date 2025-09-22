use crate::types::{MerkleNode, MerklePath};
use dashmap::{DashMap, DashSet};
use fr_common::{StateHash, StateKey};
use std::{cmp::Ordering, sync::Mutex};

pub(crate) type StateDBWrite = (StateHash, Vec<u8>);
pub(crate) type MerkleDBNodesWrite = (MerklePath, MerkleNode);
pub(crate) type MerkleDBLeafPathsWrite = (StateKey, MerklePath);

#[derive(Default)]
struct DBWriteSet {
    state_db_write_set: Vec<StateDBWrite>,
    merkle_db_nodes_write_set: Vec<MerkleDBNodesWrite>,
    merkle_db_leaf_paths_write_set: Vec<MerkleDBLeafPathsWrite>,
}

pub(crate) struct MerkleCache {
    /// Represents posterior state of merkle nodes after commiting dirty cache entries.
    map: DashMap<MerklePath, Option<MerkleNode>>,
    /// A set of merkle paths that are affected by dirty cache commitment.
    affected_paths: DashSet<MerklePath>,
    db_write_set: Mutex<DBWriteSet>,
}

impl MerkleCache {
    pub(crate) fn insert(&self, merkle_path: MerklePath, node: MerkleNode) -> Option<MerkleNode> {
        self.map.insert(merkle_path, Some(node)).flatten()
    }

    pub(crate) fn clear(&self) {
        self.map.clear();
        self.affected_paths.clear();
    }

    pub(crate) fn insert_state_db_write(&self, state_db_write: StateDBWrite) {
        self.db_write_set
            .lock()
            .unwrap()
            .state_db_write_set
            .push(state_db_write);
    }

    pub(crate) fn insert_merkle_db_nodes_write(&self, merkle_db_nodes_write: MerkleDBNodesWrite) {
        self.db_write_set
            .lock()
            .unwrap()
            .merkle_db_nodes_write_set
            .push(merkle_db_nodes_write);
    }

    pub(crate) fn insert_merkle_db_leaf_paths_write(
        &self,
        merkle_db_leaf_paths_write: MerkleDBLeafPathsWrite,
    ) {
        self.db_write_set
            .lock()
            .unwrap()
            .merkle_db_leaf_paths_write_set
            .push(merkle_db_leaf_paths_write);
    }

    pub(crate) fn affected_paths_as_sorted_vec(&self) -> Vec<MerklePath> {
        let mut affected_paths_vec = self.affected_paths.clone().into_iter().collect::<Vec<_>>();
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;

    #[test]
    fn test_affected_paths_sorting() {
        let paths = DashSet::from_iter(vec![
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 1, 1]),
            MerklePath(bitvec![u8, Msb0; 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0, 1, 0, 1]),
            MerklePath(bitvec![u8, Msb0; 1, 0]),
        ]);

        let merkle_cache = MerkleCache {
            map: DashMap::new(),
            affected_paths: paths,
            db_write_set: Mutex::new(DBWriteSet::default()),
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
}
