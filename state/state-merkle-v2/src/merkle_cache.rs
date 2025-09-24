use crate::types::{MerkleNode, MerklePath, StateMerkleError};
use fr_common::{StateHash, StateKey};
use fr_db::{
    core::cached_db::{CacheItem, DBKey},
    ColumnFamily, WriteBatch,
};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
};

pub(crate) type StateDBWrite = (StateHash, Vec<u8>);
pub(crate) type MerkleDBNodesWrite = (MerklePath, Option<MerkleNode>);
pub(crate) type MerkleDBLeafPathsWrite = (StateKey, Option<MerklePath>);

pub(crate) struct MerkleDBWriteBatch {
    pub(crate) nodes: WriteBatch,
    pub(crate) leaf_paths: WriteBatch,
}

#[derive(Default)]
pub(crate) struct DBWriteSet {
    pub(crate) state_db_write_set: Vec<StateDBWrite>,
    pub(crate) merkle_db_nodes_write_set: Vec<MerkleDBNodesWrite>,
    pub(crate) merkle_db_leaf_paths_write_set: Vec<MerkleDBLeafPathsWrite>,
}

impl DBWriteSet {
    fn append_write_entries_to_write_batch<K: DBKey, V: CacheItem>(
        cf_handle: &ColumnFamily,
        batch: &mut WriteBatch,
        write_set: &[(K, Option<V>)],
    ) -> Result<(), StateMerkleError> {
        for (k, v) in write_set {
            match v {
                Some(val) => {
                    batch.put_cf(cf_handle, k.as_db_key(), val.clone().into_db_value()?);
                }
                None => batch.delete_cf(cf_handle, k.as_db_key()),
            }
        }
        Ok(())
    }

    pub(crate) fn generate_merkle_db_write_batch(
        &self,
        merkle_nodes_cf: &ColumnFamily,
        merkle_leaf_paths_cf: &ColumnFamily,
    ) -> Result<MerkleDBWriteBatch, StateMerkleError> {
        let mut nodes = WriteBatch::default();
        let mut leaf_paths = WriteBatch::default();

        Self::append_write_entries_to_write_batch(
            merkle_nodes_cf,
            &mut nodes,
            &self.merkle_db_nodes_write_set,
        )?;
        Self::append_write_entries_to_write_batch(
            merkle_leaf_paths_cf,
            &mut leaf_paths,
            &self.merkle_db_leaf_paths_write_set,
        )?;

        Ok(MerkleDBWriteBatch { nodes, leaf_paths })
    }
}

#[derive(Default)]
pub(crate) struct MerkleCache {
    // TODO: rename to `nodes`
    /// Represents the posterior state of merkle nodes after commiting dirty cache entries.
    pub(crate) map: HashMap<MerklePath, Option<MerkleNode>>,
    /// A set of merkle paths that are affected by dirty cache commitment.
    pub(crate) affected_paths: HashSet<MerklePath>,
    pub(crate) db_write_set: DBWriteSet,
}

impl MerkleCache {
    pub(crate) fn get_node(&self, merkle_path: &MerklePath) -> Option<Option<MerkleNode>> {
        self.map.get(merkle_path).cloned()
    }

    pub(crate) fn insert(
        &mut self,
        merkle_path: MerklePath,
        node: Option<MerkleNode>,
    ) -> Option<MerkleNode> {
        self.map.insert(merkle_path, node).flatten()
    }

    /// Extends `affected_paths` set with all paths that are affected by mutating
    /// a node at the given merkle path.
    pub(crate) fn extend_affected_paths(&mut self, merkle_path: &MerklePath) {
        let affected_paths = merkle_path.all_paths_to_root();
        self.affected_paths.extend(affected_paths);
    }

    pub(crate) fn insert_to_affected_paths(&mut self, merkle_path: MerklePath) {
        self.affected_paths.insert(merkle_path);
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
    use crate::merkle_path;
    use bitvec::prelude::*;

    #[test]
    fn test_affected_paths_sorting() {
        let paths = HashSet::from_iter(vec![
            merkle_path![1, 0, 1, 1],
            merkle_path![1, 0, 1, 1, 1],
            merkle_path![1],
            merkle_path![1, 0, 1, 0, 1],
            merkle_path![1, 0],
        ]);

        let merkle_cache = MerkleCache {
            map: HashMap::new(),
            affected_paths: paths,
            db_write_set: DBWriteSet::default(),
        };
        let paths_sorted = merkle_cache.affected_paths_as_sorted_vec();

        let paths_sorted_expected = vec![
            merkle_path![1, 0, 1, 1, 1],
            merkle_path![1, 0, 1, 0, 1],
            merkle_path![1, 0, 1, 1],
            merkle_path![1, 0],
            merkle_path![1],
        ];
        assert_eq!(paths_sorted, paths_sorted_expected);
    }
}
