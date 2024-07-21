use crate::{
    common::{Hash32, Octets},
    db::manager::KVDBManager,
    trie::{
        serialization::serialize_state,
        utils::{
            bitvec_to_hash, blake2b_256, bytes_to_lsb_bits, EMPTY_HASH, lsb_bits_to_bytes,
            MerklizationError, NODE_SIZE_BITS, slice_bitvec,
        },
    },
};
use bit_vec::BitVec;
use std::collections::HashMap;
use crate::state::global_state::GlobalState;

// Merkle Trie representation and helper functions

// Node encoding functions
pub(crate) fn encode_branch(left: Hash32, right: Hash32) -> BitVec {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, false); // indicator for the Branch Node
    node.extend(slice_bitvec(&bytes_to_lsb_bits(left.to_vec()), 1..));
    node.extend(bytes_to_lsb_bits(right.to_vec()));
    node
}

pub(crate) fn encode_leaf(
    db_manager: &KVDBManager,
    key: Hash32,
    value: &Octets,
) -> Result<BitVec, MerklizationError> {
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
        let value_hash = db_manager.store_data(value)?;
        node.set(1, true); // indicator for the Regular Leaf
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(value_hash.to_vec()));
    }

    Ok(node)
}

// The state map Merklization function (`M`)
fn merklize_map(
    db_manager: &KVDBManager,
    d: HashMap<BitVec, (Hash32, Octets)>,
) -> Result<Hash32, MerklizationError> {
    if d.is_empty() {
        return Ok(EMPTY_HASH);
    }

    if d.len() == 1 {
        let (_bits_key, (k, v)) = d.into_iter().next().unwrap();
        let leaf = encode_leaf(db_manager, k, &v)?; // this involves storing data the leaf node points to the KVDB.
        let leaf_bytes = lsb_bits_to_bytes(leaf.clone());
        let leaf_hash = blake2b_256(&leaf_bytes)?;
        db_manager.store_node(&leaf_hash, &leaf_bytes)?; // key: Hash(value), value: bits^-1(L(k, v))
        return Ok(leaf_hash);
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
    let left_hash = merklize_map(db_manager, left)?;
    let right_hash = merklize_map(db_manager, right)?;
    let branch = encode_branch(left_hash, right_hash);
    let branch_bytes = lsb_bits_to_bytes(branch.clone());
    let branch_hash = blake2b_256(&branch_bytes)?;
    db_manager.store_node(&branch_hash, &branch_bytes)?;
    Ok(branch_hash)
}

// The basic Merklization function (`M_sigma`)
fn merklize_state(
    db_manager: &KVDBManager,
    state: &GlobalState,
) -> Result<Hash32, MerklizationError> {
    let serialized_state = serialize_state(state);
    let mut state_map = HashMap::new();
    for (k, v) in serialized_state {
        state_map.insert(bytes_to_lsb_bits(k.to_vec()), (k, v));
    }
    merklize_map(db_manager, state_map)
}

pub(crate) fn retrieve(
    db_manager: &KVDBManager,
    root_hash: Hash32,
    merkle_path: BitVec,
) -> Result<Octets, MerklizationError> {
    let mut current_node_hash = root_hash;

    for bit in merkle_path {
        // If branch node, proceed. If leaf node, fetch the data
        if is_leaf(db_manager, &current_node_hash)? {
            let data = get_data_from_leaf_hash(db_manager, &current_node_hash)?;
            return Ok(data);
        }
        current_node_hash = get_child_hash(db_manager, current_node_hash, !bit)?;
    }

    // Final node should be a leaf node
    if is_leaf(db_manager, &current_node_hash)? {
        let data = get_data_from_leaf_hash(db_manager, &current_node_hash)?;
        return Ok(data);
    }

    Err(MerklizationError::NodeNotFound)
}

fn get_child_hash(
    db_manager: &KVDBManager,
    node_hash: Hash32,
    left: bool,
) -> Result<Hash32, MerklizationError> {
    // note: only branch node should call this
    let node_bytes = db_manager.get_node(&node_hash)?;
    let node_bits = bytes_to_lsb_bits(node_bytes);

    let hash_bits = if left {
        slice_bitvec(&node_bits, 1..(NODE_SIZE_BITS / 2)) // index 0 for branch identifier
    } else {
        slice_bitvec(&node_bits, (NODE_SIZE_BITS / 2)..NODE_SIZE_BITS) // index 0 for branch identifier
    };

    lsb_bits_to_bytes(hash_bits)
        .try_into()
        .map_err(|_| MerklizationError::HashLengthMismatchError)
}

fn is_leaf(db_manager: &KVDBManager, node_hash: &Hash32) -> Result<bool, MerklizationError> {
    let node_bytes = db_manager.get_node(&node_hash)?;
    let node_bits = bytes_to_lsb_bits(node_bytes);

    Ok(node_bits[0])
}

fn get_data_from_leaf_hash(
    db_manager: &KVDBManager,
    leaf_hash: &Hash32,
) -> Result<Octets, MerklizationError> {
    let node_bytes = db_manager.get_node(&leaf_hash)?;
    let node_bits = bytes_to_lsb_bits(node_bytes);
    let data_hash = bitvec_to_hash(slice_bitvec(&node_bits, 256..))?;
    db_manager.get_node(&data_hash)
}
