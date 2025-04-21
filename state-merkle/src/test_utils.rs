use crate::{codec::NodeCodec, merkle_db::MerkleDB, types::nodes::MerkleNode};
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};
//
// Helper Functions
//

pub fn simple_hash(seed: &str) -> Hash32 {
    hash::<Blake2b256>(seed.as_bytes()).unwrap()
}

/// Returns 10-byte blob
pub fn some_small_blob() -> Vec<u8> {
    hex::decode("00112233445566778899").unwrap()
}

/// Returns 100-byte blob
pub fn some_large_blob() -> Vec<u8> {
    hex::decode(
        "00112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899001122334455667788990011223344556677889900112233445566778899",
    )
        .unwrap()
}

pub fn generate_branch(left: Hash32, right: Hash32) -> MerkleNode {
    let node_data = NodeCodec::encode_branch(&left, &right).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    // println!(
    //     "+++ Generated Branch: Hash({}), Left({}), Right({})",
    //     &node_hash, &left_hash, &right_hash,
    // );
    MerkleNode::new(node_hash, node_data)
}

pub fn generate_embedded_leaf(state_key: Hash32, state_value: &[u8]) -> MerkleNode {
    if state_value.len() > 32 {
        panic!("State data too large for embedded leaf")
    }
    let node_data = NodeCodec::encode_leaf(&state_key, state_value).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    // println!(
    //     "+++ Generated Embedded: Hash({}), EmbeddedStateValue({})",
    //     &node_hash,
    //     hex::encode(&state_value)
    // );
    MerkleNode::new(node_hash, node_data)
}

pub fn generate_regular_leaf(state_key: Hash32, state_value: &[u8]) -> MerkleNode {
    if state_value.len() <= 32 {
        panic!("State data too small for regular leaf")
    }

    let node_data = NodeCodec::encode_leaf(&state_key, state_value).unwrap();
    let node_hash = hash::<Blake2b256>(&node_data).unwrap();
    // println!(
    //     "+++ Generated Regular: Hash({}), StateValueHash({})",
    //     &node_hash,
    //     hash::<Blake2b256>(&state_value).unwrap(),
    // );
    MerkleNode::new(node_hash, node_data)
}

pub async fn print_node(node: &Option<MerkleNode>, merkle_db: &MerkleDB) {
    match node {
        Some(node) => {
            println!(
                ">>> Node: {}",
                node.parse_node_data(merkle_db).await.unwrap()
            );
        }
        None => println!(">>> None"),
    }
}
