use crate::{
    merkle_db::MerkleDB,
    types::{BranchNode, LeafNode, LeafNodeData, MerklePath},
    utils::bits_decode_msb,
};
use bitvec::prelude::*;
use fr_common::{ByteEncodable, NodeHash, StateKey, STATE_KEY_SIZE};
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

pub(crate) fn create_regular_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> LeafNode {
    LeafNode::new(
        state_key_bv,
        LeafNodeData::Regular(hash::<Blake2b256>(&data).unwrap()),
    )
}

pub(crate) fn create_embedded_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> LeafNode {
    LeafNode::new(state_key_bv, LeafNodeData::Embedded(data))
}

pub(crate) fn create_branch(left_hash: &NodeHash, right_hash: &NodeHash) -> BranchNode {
    BranchNode::new(left_hash, right_hash)
}

pub(crate) fn create_dummy_embedded_leaf(seed: u8) -> LeafNode {
    let state_key_bv = bitvec![u8, Msb0; 0, 1, 1, 1];
    let data = vec![seed; 32];
    LeafNode::new(state_key_bv, LeafNodeData::Embedded(data))
}

pub(crate) fn create_dummy_regular_leaf(seed: u8) -> LeafNode {
    let state_key_bv = bitvec![u8, Msb0; 0, 1, 1, 1];
    let data = vec![seed; 32];
    LeafNode::new(
        state_key_bv,
        LeafNodeData::Regular(hash::<Blake2b256>(&data).unwrap()),
    )
}

pub(crate) fn create_dummy_branch(seed: u8) -> BranchNode {
    BranchNode::new(
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
    )
}

pub(crate) fn create_dummy_single_child_branch(seed: u8) -> BranchNode {
    BranchNode::new(
        &NodeHash::from_slice(&[0; 32]).unwrap(),
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
    )
}

pub(crate) fn create_state_key_from_path_prefix(path_prefix: MerklePath) -> StateKey {
    let mut state_key_bv = bits_decode_msb(path_prefix.0);
    state_key_bv.resize(STATE_KEY_SIZE, 0);
    StateKey::new(state_key_bv.try_into().unwrap())
}

#[macro_export]
macro_rules! merkle_path {
    ($($val:expr),*) => {
        MerklePath(bitvec![u8, Msb0; $($val),*])
    };
}
