use crate::types::{LeafNode, MerkleNode, MerklePath, StateMerkleError};
use fr_common::{MerkleRoot, StateKey};
use fr_db::{
    core::{cached_db::CachedDB, core_db::CoreDB},
    Direction, IteratorMode, WriteBatch,
};
use std::sync::Arc;

pub(crate) struct MerkleDB {
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

    pub(crate) async fn find_longest_prefix(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<MerklePath>, StateMerkleError> {
        let core_db = self.nodes.core.clone();
        let state_key_vec = state_key.to_vec();
        let nodes_cf_handle = self.nodes.cf_name;

        tokio::task::spawn_blocking(move || -> Result<_, StateMerkleError> {
            let mut iter = core_db.iterator_cf(
                nodes_cf_handle,
                IteratorMode::From(&state_key_vec, Direction::Reverse),
            )?;

            // Get the first key from the iterator
            if let Some(Ok((candidate_key, _))) = iter.next() {
                if state_key_vec.starts_with(&candidate_key) {
                    let key_vec = candidate_key.into_vec();
                    let merkle_path = MerklePath::from(key_vec);
                    return Ok(Some(merkle_path));
                }
            }

            // No key found or the found key was not a prefix
            Ok(None)
        })
        .await?
    }

    pub(crate) fn root(&self) -> &MerkleRoot {
        &self.root
    }

    pub(crate) fn update_root(&mut self, new_root: MerkleRoot) {
        self.root = new_root;
    }

    pub(crate) async fn get(
        &self,
        merkle_path: &MerklePath,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        Ok(self.nodes.get_entry(merkle_path).await?)
    }

    pub(crate) async fn get_leaf_path(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<MerklePath>, StateMerkleError> {
        Ok(self.leaf_paths.get_entry(state_key).await?)
    }

    pub(crate) async fn get_leaf(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<LeafNode>, StateMerkleError> {
        if let Some(leaf_merkle_path) = self.get_leaf_path(state_key).await? {
            if let Some(MerkleNode::Leaf(leaf)) = self.get(&leaf_merkle_path).await? {
                return Ok(Some(leaf));
            }
        }
        Ok(None)
    }

    pub(crate) async fn put(
        &self,
        merkle_path: &MerklePath,
        node: MerkleNode,
    ) -> Result<(), StateMerkleError> {
        Ok(self.nodes.put_entry(merkle_path, node).await?)
    }

    async fn put_leaf_path(
        &self,
        state_key: &StateKey,
        leaf_path: MerklePath,
    ) -> Result<(), StateMerkleError> {
        Ok(self.leaf_paths.put_entry(state_key, leaf_path).await?)
    }

    pub(crate) async fn put_leaf(
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
        nodes_batch: WriteBatch,
        leaf_paths_batch: WriteBatch,
    ) -> Result<(), StateMerkleError> {
        self.nodes.commit_write_batch(nodes_batch).await?;
        self.leaf_paths.commit_write_batch(leaf_paths_batch).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::open_merkle_db,
        types::{BranchNode, LeafNode, LeafNodeData},
        utils::bits_encode_msb,
    };
    use bitvec::prelude::*;
    use fr_common::{ByteEncodable, Hash32, NodeHash};

    #[tokio::test]
    async fn test_node_entries() {
        let merkle_db = open_merkle_db();
        let merkle_path = MerklePath(bitvec![u8, Msb0; 0, 0, 1]);

        assert_eq!(merkle_db.get(&merkle_path).await.unwrap(), None);

        let branch_node = MerkleNode::Branch(BranchNode::new(
            &NodeHash::from_slice(&[0xAA; 32]).unwrap(),
            &NodeHash::from_slice(&[0xBB; 32]).unwrap(),
        ));
        merkle_db
            .put(&merkle_path, branch_node.clone())
            .await
            .unwrap();
        assert_eq!(
            merkle_db.get(&merkle_path).await.unwrap(),
            Some(branch_node)
        );
    }

    #[tokio::test]
    async fn test_leaf_entries() {
        let merkle_db = open_merkle_db();
        let state_key = StateKey::from_slice(&[0xCC; 31]).unwrap();
        let state_key_bv = bits_encode_msb(state_key.as_slice());

        let leaf_path = MerklePath(bitvec![u8, Msb0; 0, 1, 1, 1]);
        let leaf_node = LeafNode::new(state_key_bv, LeafNodeData::Regular(Hash32::new([0xDD; 32])));

        assert_eq!(merkle_db.get_leaf(&state_key).await.unwrap(), None);

        merkle_db
            .put_leaf(&state_key, leaf_path, leaf_node.clone())
            .await
            .unwrap();

        assert_eq!(
            merkle_db.get_leaf(&state_key).await.unwrap(),
            Some(leaf_node)
        );
    }
}
