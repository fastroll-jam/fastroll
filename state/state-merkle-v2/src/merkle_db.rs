use crate::{
    merkle_change_set::{MerkleDBLeafPathsWrite, MerkleDBNodesWrite, MerkleDBWriteBatch},
    types::{LeafNode, MerkleNode, MerklePath, StateMerkleError},
    utils::bits_encode_msb,
};
use bitvec::vec::BitVec;
use fr_common::{MerkleRoot, StateKey};
use fr_db::{
    core::{
        cached_db::{CachedDB, DBKey},
        core_db::CoreDB,
    },
    ColumnFamily, Direction, IteratorMode,
};
use std::sync::Arc;

pub struct MerkleDB {
    nodes: CachedDB<MerklePath, MerkleNode>,
    leaf_paths: CachedDB<StateKey, MerklePath>,
    root: MerkleRoot,
}

impl MerkleDB {
    pub fn new(
        core: Arc<CoreDB>,
        nodes_cf_name: &'static str,
        leaf_paths_cf_name: &'static str,
        cache_size: usize,
    ) -> Self {
        Self {
            nodes: CachedDB::new(core.clone(), nodes_cf_name, cache_size),
            leaf_paths: CachedDB::new(core.clone(), leaf_paths_cf_name, cache_size),
            root: MerkleRoot::default(),
        }
    }

    pub fn nodes_cf_handle(&self) -> Result<&ColumnFamily, StateMerkleError> {
        Ok(self.nodes.cf_handle()?)
    }

    pub fn leaf_paths_cf_handle(&self) -> Result<&ColumnFamily, StateMerkleError> {
        Ok(self.leaf_paths.cf_handle()?)
    }

    /// Finds the longest Merkle path in the `MerkleDB` that is a prefix of a given state key.
    pub async fn find_longest_prefix(
        &self,
        state_key: &StateKey,
    ) -> Result<MerklePath, StateMerkleError> {
        let core_db = self.nodes.core.clone();
        let nodes_cf_handle = self.nodes.cf_name;

        // Temporary path for searching the longest prefix path, representing
        // the state key as a full merkle path.
        let search_path = MerklePath(bits_encode_msb(state_key.as_slice()));
        let search_db_key = search_path.as_db_key().into_owned().into_boxed_slice();

        // Create a merkle path with the first bit of `search_path` to initialize
        // `longest_prefix` variable below. We start iterating DB keys from this path.
        let start_key = MerklePath(search_path.0[0..1].to_bitvec())
            .as_db_key()
            .into_owned();

        tokio::task::spawn_blocking(move || -> Result<_, StateMerkleError> {
            let mut longest_prefix = MerklePath(BitVec::new());

            let mut iter = core_db.iterator_cf(
                nodes_cf_handle,
                IteratorMode::From(&start_key, Direction::Forward),
            )?;

            // Iterate on DB keys until we find a DB key which becomes the longest prefix of `state_key`
            while let Some(Ok((candidate_db_key, _))) = iter.next() {
                let candidate_path = MerklePath::from_db_key(&candidate_db_key)?;

                // Reached to a DB key with larger value; no need to check further
                if candidate_db_key > search_db_key {
                    break;
                }

                if search_path.0.starts_with(&candidate_path.0) {
                    // Found a longer prefix; update `longest_prefix`
                    longest_prefix = candidate_path;
                }
            }

            Ok(longest_prefix)
        })
        .await?
    }

    #[allow(dead_code)]
    pub(crate) fn root(&self) -> &MerkleRoot {
        &self.root
    }

    pub fn update_root(&mut self, new_root: MerkleRoot) {
        self.root = new_root;
    }

    pub async fn get_node(
        &self,
        merkle_path: &MerklePath,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        Ok(self.nodes.get_entry(merkle_path).await?)
    }

    pub async fn get_leaf_path(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<MerklePath>, StateMerkleError> {
        Ok(self.leaf_paths.get_entry(state_key).await?)
    }

    pub async fn get_leaf(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<LeafNode>, StateMerkleError> {
        if let Some(leaf_merkle_path) = self.get_leaf_path(state_key).await? {
            if let Some(MerkleNode::Leaf(leaf)) = self.get_node(&leaf_merkle_path).await? {
                return Ok(Some(leaf));
            }
        }
        Ok(None)
    }

    pub async fn insert_node(
        &self,
        merkle_path: &MerklePath,
        node: MerkleNode,
    ) -> Result<(), StateMerkleError> {
        Ok(self.nodes.put_entry(merkle_path, node).await?)
    }

    #[allow(dead_code)]
    async fn insert_leaf_path(
        &self,
        state_key: &StateKey,
        leaf_path: MerklePath,
    ) -> Result<(), StateMerkleError> {
        Ok(self.leaf_paths.put_entry(state_key, leaf_path).await?)
    }

    pub async fn insert_leaf(
        &self,
        state_key: &StateKey,
        leaf_path: MerklePath,
        leaf_node: LeafNode,
    ) -> Result<(), StateMerkleError> {
        self.nodes
            .put_entry(&leaf_path, MerkleNode::Leaf(leaf_node))
            .await?;
        self.leaf_paths.put_entry(state_key, leaf_path).await?;
        Ok(())
    }

    /// Commit write batches for node entries and leaf node entries into the MerkleDB.
    pub async fn commit_write_batch(
        &self,
        batch: MerkleDBWriteBatch,
        nodes_writes: &[MerkleDBNodesWrite],
        leaf_paths_writes: &[MerkleDBLeafPathsWrite],
    ) -> Result<(), StateMerkleError> {
        self.nodes
            .commit_write_batch_and_sync_cache(batch.nodes, nodes_writes)
            .await?;
        self.leaf_paths
            .commit_write_batch_and_sync_cache(batch.leaf_paths, leaf_paths_writes)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle_path,
        test_utils::{create_branch, open_merkle_db},
        types::{LeafNode, LeafNodeData},
        utils::bits_encode_msb,
    };
    use bitvec::prelude::*;
    use fr_common::{ByteEncodable, Hash32, NodeHash};

    #[tokio::test]
    async fn test_node_entries() {
        let merkle_db = open_merkle_db();
        let merkle_path = merkle_path![0, 0, 1];

        assert_eq!(merkle_db.get_node(&merkle_path).await.unwrap(), None);

        let branch_node = MerkleNode::Branch(create_branch(
            &NodeHash::from_slice(&[0xAA; 32]).unwrap(),
            &NodeHash::from_slice(&[0xBB; 32]).unwrap(),
        ));
        merkle_db
            .insert_node(&merkle_path, branch_node.clone())
            .await
            .unwrap();
        assert_eq!(
            merkle_db.get_node(&merkle_path).await.unwrap(),
            Some(branch_node)
        );
    }

    #[tokio::test]
    async fn test_leaf_entries() {
        let merkle_db = open_merkle_db();
        let state_key = StateKey::from_slice(&[0xCC; 31]).unwrap();
        let state_key_bv = bits_encode_msb(state_key.as_slice());

        let leaf_path = merkle_path![0, 1, 1, 1];
        let leaf_node = LeafNode::new(state_key_bv, LeafNodeData::Regular(Hash32::new([0xDD; 32])));

        assert_eq!(merkle_db.get_leaf(&state_key).await.unwrap(), None);

        merkle_db
            .insert_leaf(&state_key, leaf_path, leaf_node.clone())
            .await
            .unwrap();

        assert_eq!(
            merkle_db.get_leaf(&state_key).await.unwrap(),
            Some(leaf_node)
        );
    }
}
