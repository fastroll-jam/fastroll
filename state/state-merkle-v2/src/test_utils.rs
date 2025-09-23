use crate::{
    merkle_db::MerkleDB,
    types::{BranchNode, LeafNode, LeafNodeData, MerkleNode},
};
use bitvec::prelude::*;
use fr_common::NodeHash;
use fr_config::{StorageConfig, MERKLE_CF_NAME, MERKLE_LEAF_PATHS_CF_NAME};
use fr_crypto::{hash, Blake2b256};
use fr_db::core::core_db::CoreDB;
use std::sync::Arc;
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

pub(crate) fn open_merkle_db() -> MerkleDB {
    let core_db = open_core_db();
    MerkleDB::new(
        Arc::new(core_db),
        MERKLE_CF_NAME,
        MERKLE_LEAF_PATHS_CF_NAME,
        4096,
    )
}

pub(crate) fn create_regular_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> MerkleNode {
    MerkleNode::Leaf(LeafNode::new(
        state_key_bv,
        LeafNodeData::Regular(hash::<Blake2b256>(&data).unwrap()),
    ))
}

pub(crate) fn create_embedded_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> MerkleNode {
    MerkleNode::Leaf(LeafNode::new(state_key_bv, LeafNodeData::Embedded(data)))
}

pub(crate) fn create_branch(left_hash: &NodeHash, right_hash: &NodeHash) -> MerkleNode {
    MerkleNode::Branch(BranchNode::new(left_hash, right_hash))
}

#[macro_export]
macro_rules! merkle_path {
    ($($val:expr),*) => {
        MerklePath(bitvec![u8, Msb0; $($val),*])
    };
}
