use crate::types::{MerkleNode, MerklePath};
use fr_common::{StateHash, StateKey};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

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
    map: HashMap<MerklePath, Option<MerkleNode>>,
    /// A set of merkle paths that are affected by dirty cache commitment.
    affected_paths: HashSet<MerklePath>,
    db_write_set: DBWriteSet,
}

impl MerkleCache {
    pub(crate) fn insert(
        &mut self,
        merkle_path: MerklePath,
        node: MerkleNode,
    ) -> Option<MerkleNode> {
        self.map.insert(merkle_path, Some(node)).flatten()
    }

    /// Extends `affected_paths` set with all paths that are affected by mutating
    /// a node at the given merkle path.
    pub(crate) fn extend_affected_paths(&mut self, merkle_path: &MerklePath) {
        let affected_paths = merkle_path.all_paths_to_root();
        self.affected_paths.extend(affected_paths);
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.affected_paths.clear();
    }

    pub(crate) fn insert_state_db_write(&mut self, state_db_write: StateDBWrite) {
        self.db_write_set.state_db_write_set.push(state_db_write);
    }

    pub(crate) fn insert_merkle_db_nodes_write(
        &mut self,
        merkle_db_nodes_write: MerkleDBNodesWrite,
    ) {
        self.db_write_set
            .merkle_db_nodes_write_set
            .push(merkle_db_nodes_write);
    }

    pub(crate) fn insert_merkle_db_leaf_paths_write(
        &mut self,
        merkle_db_leaf_paths_write: MerkleDBLeafPathsWrite,
    ) {
        self.db_write_set
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
            db_write_set: DBWriteSet::default(),
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
