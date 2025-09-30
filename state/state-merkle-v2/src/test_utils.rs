use crate::{
    merkle_db::MerkleDB,
    types::{BranchNode, LeafNode, LeafNodeData, MerklePath},
    utils::bits_decode_msb,
};
use bitvec::prelude::*;
use fr_common::{ByteEncodable, NodeHash, StateKey, STATE_KEY_SIZE};
use fr_config::{
    StorageConfig, MERKLE_CF_NAME, MERKLE_DB_CACHE_SIZE, MERKLE_LEAF_PATHS_CF_NAME,
    MERKLE_LEAF_PATHS_DB_CACHE_SIZE,
};
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

pub fn open_merkle_db() -> MerkleDB {
    let core_db = open_core_db();
    MerkleDB::new(
        Arc::new(core_db),
        MERKLE_CF_NAME,
        MERKLE_LEAF_PATHS_CF_NAME,
        MERKLE_DB_CACHE_SIZE,
        MERKLE_LEAF_PATHS_DB_CACHE_SIZE,
    )
}

pub fn create_regular_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> LeafNode {
    LeafNode::new(
        state_key_bv,
        LeafNodeData::Regular(hash::<Blake2b256>(&data).unwrap()),
    )
}

pub fn create_embedded_leaf(state_key_bv: BitVec<u8, Msb0>, data: Vec<u8>) -> LeafNode {
    LeafNode::new(state_key_bv, LeafNodeData::Embedded(data))
}

pub fn create_branch(left_hash: &NodeHash, right_hash: &NodeHash) -> BranchNode {
    BranchNode::new(left_hash, right_hash)
}

pub fn create_dummy_embedded_leaf(seed: u8) -> LeafNode {
    let state_key_bv = bitvec![u8, Msb0; 1; 248];
    let data = vec![seed; 32];
    LeafNode::new(state_key_bv, LeafNodeData::Embedded(data))
}

pub fn create_dummy_regular_leaf(seed: u8) -> LeafNode {
    let state_key_bv = bitvec![u8, Msb0; 1; 248];
    let data = vec![seed; 32];
    LeafNode::new(
        state_key_bv,
        LeafNodeData::Regular(hash::<Blake2b256>(&data).unwrap()),
    )
}

pub fn create_dummy_branch(seed: u8) -> BranchNode {
    BranchNode::new(
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
    )
}

pub fn create_dummy_single_child_branch(seed: u8) -> BranchNode {
    BranchNode::new(
        &NodeHash::from_slice(&[0; 32]).unwrap(),
        &NodeHash::from_slice(&[seed; 32]).unwrap(),
    )
}

pub fn create_state_key_from_path_prefix(path_prefix: MerklePath) -> StateKey {
    let mut state_key_decoded = bits_decode_msb(path_prefix.0);
    state_key_decoded.resize(STATE_KEY_SIZE, 0);
    StateKey::new(state_key_decoded.try_into().unwrap())
}

#[macro_export]
macro_rules! merkle_path {
    ($($val:expr),*) => {
        MerklePath(bitvec![u8, Msb0; $($val),*])
    };
}
