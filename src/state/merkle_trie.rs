use crate::common::{Hash32, Octets};
use crate::state::{
    db::KeyValueDB,
    serialization::serialize_state,
    utils::{
        blake2b_256, bytes_to_lsb_bits, lsb_bits_to_bytes, slice_bitvec, EMPTY_HASH, NODE_SIZE_BITS,
    },
    GlobalState,
};
use bit_vec::BitVec;
use std::collections::HashMap;

// Merkle Trie representation and helper functions

// KVDB interactions
fn store_node(db: &dyn KeyValueDB, hash: Hash32, serialized_node: &[u8]) {
    db.put(&hash, serialized_node)
        .expect("Failed to store node");
}

pub(crate) fn store_data(db: &dyn KeyValueDB, data: &[u8]) -> Hash32 {
    let data_hash = blake2b_256(data);
    db.put(&data_hash, data).expect("Failed to store data");
    data_hash
}

fn get_node(db: &dyn KeyValueDB, hash: &Hash32) -> Option<Vec<u8>> {
    db.get(hash).expect("Failed to get node")
}

// Node encoding functions
pub(crate) fn encode_branch(left: Hash32, right: Hash32) -> BitVec {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, false); // indicator for the Branch Node
    node.extend(slice_bitvec(&bytes_to_lsb_bits(left.to_vec()), 1..));
    node.extend(bytes_to_lsb_bits(right.to_vec()));
    node
}

pub(crate) fn encode_leaf(db: &dyn KeyValueDB, key: Hash32, value: Octets) -> BitVec {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, true); // indicator for the Leaf Node
    if value.len() <= 32 {
        node.set(1, false); // indicator for the Embedded-value Leaf
        let length_bits = bytes_to_lsb_bits(vec![value.len() as u8]); // E_1 SCALE integer encoding

        for i in 0..6 {
            node.set(2 + i, length_bits[i]); // 6 bits for the embedded value size
        }
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(value.to_vec()));

        while node.len() < NODE_SIZE_BITS {
            node.push(false); // filling the remaining bits with zeroes
        }
    } else {
        let value_hash = store_data(db, &value); // store the data to the KVDB.
        node.set(1, true); // indicator for the Regular Leaf
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(value_hash.to_vec()));
    }

    node
}

// The state map Merklization function (`M`)
fn merklize_map(db: &dyn KeyValueDB, d: HashMap<BitVec, (Hash32, Octets)>) -> Hash32 {
    if d.is_empty() {
        return EMPTY_HASH;
    }

    if d.len() == 1 {
        let (_bits_key, (k, v)) = d.into_iter().next().unwrap();
        let leaf = encode_leaf(db, k, v); // this involves storing data the leaf node points to the KVDB.
        let leaf_bytes = lsb_bits_to_bytes(leaf.clone());
        let leaf_hash = blake2b_256(&leaf_bytes);
        store_node(db, leaf_hash, &leaf_bytes); // key: Hash(value), value: bits^-1(L(k, v))
        return leaf_hash;
    }

    let mut left = HashMap::new();
    let mut right = HashMap::new();
    for (bits_key, p) in d {
        let key = bits_key.clone();
        if key[0] {
            right.insert(slice_bitvec(&key, 1..), p); // b0 = 1
        } else {
            left.insert(slice_bitvec(&key, 1..), p); // b0 = 0
        }
    }
    let left_hash = merklize_map(db, left);
    let right_hash = merklize_map(db, right);
    let branch = encode_branch(left_hash, right_hash);
    let branch_bytes = lsb_bits_to_bytes(branch.clone());
    let branch_hash = blake2b_256(&branch_bytes);
    store_node(db, branch_hash, &branch_bytes);
    branch_hash
}

// The basic Merklization function (`M_sigma`)
fn merklize_state(db: &dyn KeyValueDB, state: &GlobalState) -> Hash32 {
    let serialized_state = serialize_state(state);
    let mut state_map = HashMap::new();
    for (k, v) in serialized_state {
        state_map.insert(bytes_to_lsb_bits(k.to_vec()), (k, v));
    }
    merklize_map(db, state_map)
}
