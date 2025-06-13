use crate::{codec::NodeCodec, types::nodes::MerkleNode};
use fr_common::{Hash32, StateKey};
use fr_crypto::{hash, Blake2b256};

pub fn simple_hash(seed: &str) -> Hash32 {
    hash::<Blake2b256>(seed.as_bytes()).unwrap()
}

/// Returns 10-byte blob
pub fn some_small_blob() -> Vec<u8> {
    hex::decode("00112233445566778899").unwrap()
}

/// Returns 100-byte blob
pub fn some_blob() -> Vec<u8> {
    hex::decode(
        "00112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899",
    )
        .unwrap()
}

pub fn generate_branch(left: Hash32, right: Hash32) -> MerkleNode {
    let node_data = NodeCodec::encode_branch(&left, &right, None).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    tracing::trace!(
        "+++ Generated Branch: Hash({}), Left({}), Right({})",
        &node_hash,
        &left,
        &right,
    );
    MerkleNode::new(node_hash, node_data)
}

pub fn generate_embedded_leaf(state_key: StateKey, state_val: &[u8]) -> MerkleNode {
    if state_val.len() > 32 {
        panic!("State data too large for embedded leaf")
    }
    let node_data = NodeCodec::encode_leaf(&state_key, state_val).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    tracing::trace!(
        "+++ Generated Embedded: Hash({}), EmbeddedStateValue({})",
        &node_hash,
        hex::encode(state_val)
    );
    MerkleNode::new(node_hash, node_data)
}

pub fn generate_regular_leaf(state_key: StateKey, state_val: &[u8]) -> MerkleNode {
    if state_val.len() <= 32 {
        panic!("State data too small for regular leaf")
    }

    let node_data = NodeCodec::encode_leaf(&state_key, state_val).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    tracing::trace!(
        "+++ Generated Regular: Hash({}), StateValueHash({})",
        &node_hash,
        hash::<Blake2b256>(state_val).unwrap(),
    );
    MerkleNode::new(node_hash, node_data)
}
