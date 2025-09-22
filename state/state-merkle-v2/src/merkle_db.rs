use crate::types::{LeafNode, MerkleNode, MerklePath, StateMerkleError};
use fr_common::{MerkleRoot, StateKey};
use fr_db::{
    core::{cached_db::CachedDB, core_db::CoreDB},
    WriteBatch,
};
use std::sync::Arc;

pub(crate) struct MerkleDB {
    nodes: CachedDB<MerklePath, MerkleNode>,
    leaf_nodes: CachedDB<StateKey, LeafNode>,
    root: MerkleRoot,
}

impl MerkleDB {
    pub fn new(
        core: Arc<CoreDB>,
        nodes_cf_name: &'static str,
        leaf_nodes_cf_name: &'static str,
        cache_size: usize,
    ) -> Self {
        Self {
            nodes: CachedDB::new(core.clone(), nodes_cf_name, cache_size),
            leaf_nodes: CachedDB::new(core.clone(), leaf_nodes_cf_name, cache_size),
            root: MerkleRoot::default(),
        }
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

    pub(crate) async fn get_leaf(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<LeafNode>, StateMerkleError> {
        Ok(self.leaf_nodes.get_entry(state_key).await?)
    }

    pub(crate) async fn put(
        &self,
        merkle_path: &MerklePath,
        node: MerkleNode,
    ) -> Result<(), StateMerkleError> {
        Ok(self.nodes.put_entry(merkle_path, node).await?)
    }

    pub(crate) async fn put_leaf(
        &self,
        state_key: &StateKey,
        leaf_node: LeafNode,
    ) -> Result<(), StateMerkleError> {
        Ok(self.leaf_nodes.put_entry(state_key, leaf_node).await?)
    }

    /// Commit write batches for node entries and leaf node entries into the MerkleDB.
    pub async fn commit_write_batch(
        &self,
        nodes_batch: WriteBatch,
        leaf_nodes_batch: WriteBatch,
    ) -> Result<(), StateMerkleError> {
        self.nodes.commit_write_batch(nodes_batch).await?;
        self.leaf_nodes.commit_write_batch(leaf_nodes_batch).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{BranchNode, LeafNodeData},
        utils::bits_encode_msb,
    };
    use bitvec::prelude::*;
    use fr_common::{ByteEncodable, Hash32, NodeHash};
    use fr_config::{StorageConfig, MERKLE_CF_NAME, MERKLE_LEAF_CF_NAME};
    use tempfile::tempdir;

    fn open_core_db() -> CoreDB {
        let db_path = tempdir().unwrap().path().join("test_db");
        CoreDB::open(
            db_path,
            StorageConfig::rocksdb_opts(),
            StorageConfig::cf_descriptors(),
        )
        .unwrap()
    }

    fn open_merkle_db() -> MerkleDB {
        let core_db = open_core_db();
        MerkleDB::new(Arc::new(core_db), MERKLE_CF_NAME, MERKLE_LEAF_CF_NAME, 4096)
    }

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

        assert_eq!(merkle_db.get_leaf(&state_key).await.unwrap(), None);

        let leaf_node = LeafNode::new(state_key_bv, LeafNodeData::Regular(Hash32::new([0xDD; 32])));
        merkle_db
            .put_leaf(&state_key, leaf_node.clone())
            .await
            .unwrap();
        assert_eq!(
            merkle_db.get_leaf(&state_key).await.unwrap(),
            Some(leaf_node)
        );
    }
}
