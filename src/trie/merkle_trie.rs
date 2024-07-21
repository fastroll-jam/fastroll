use crate::{
    common::{Hash32, Octets},
    state::global_state::GlobalState,
    trie::{
        db::KeyValueDB,
        serialization::serialize_state,
        utils::{
            bitvec_to_hash, blake2b_256, bytes_to_lsb_bits, lsb_bits_to_bytes, slice_bitvec,
            MerklizationError, EMPTY_HASH, NODE_SIZE_BITS,
        },
    },
};
use bit_vec::BitVec;
use std::collections::HashMap;

// Merkle Trie representation and helper functions

// KVDB interactions
fn store_node(
    db: &dyn KeyValueDB,
    hash: &Hash32,
    serialized_node: &[u8],
) -> Result<(), MerklizationError> {
    db.put(hash, serialized_node)
        .map_err(|_| MerklizationError::StoreNodeError)
}

pub(crate) fn store_data(db: &dyn KeyValueDB, data: &[u8]) -> Result<Hash32, MerklizationError> {
    let data_hash = blake2b_256(data)?;
    db.put(&data_hash, data)
        .map_err(|_| MerklizationError::StoreNodeError)?;
    Ok(data_hash)
}

fn get_node(db: &dyn KeyValueDB, hash: &Hash32) -> Result<Octets, MerklizationError> {
    db.get(hash)
        .map_err(|_| MerklizationError::GetNodeError)
        .and_then(|opt| opt.ok_or(MerklizationError::NodeNotFound))
}

// Node encoding functions
pub(crate) fn encode_branch(left: Hash32, right: Hash32) -> BitVec {
    let mut node = BitVec::from_elem(NODE_SIZE_BITS, false);
    node.set(0, false); // indicator for the Branch Node
    node.extend(slice_bitvec(&bytes_to_lsb_bits(left.to_vec()), 1..));
    node.extend(bytes_to_lsb_bits(right.to_vec()));
    node
}

pub(crate) fn encode_leaf(
    db: &dyn KeyValueDB,
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
        let value_hash = store_data(db, value)?; // store the data to the KVDB.
        node.set(1, true); // indicator for the Regular Leaf
        node.extend(slice_bitvec(&bytes_to_lsb_bits(key.to_vec()), 0..248));
        node.extend(bytes_to_lsb_bits(value_hash.to_vec()));
    }

    Ok(node)
}

// The state map Merklization function (`M`)
fn merklize_map(
    db: &dyn KeyValueDB,
    d: HashMap<BitVec, (Hash32, Octets)>,
) -> Result<Hash32, MerklizationError> {
    if d.is_empty() {
        return Ok(EMPTY_HASH);
    }

    if d.len() == 1 {
        let (_bits_key, (k, v)) = d.into_iter().next().unwrap();
        let leaf = encode_leaf(db, k, &v)?; // this involves storing data the leaf node points to the KVDB.
        let leaf_bytes = lsb_bits_to_bytes(leaf.clone());
        let leaf_hash = blake2b_256(&leaf_bytes)?;
        store_node(db, &leaf_hash, &leaf_bytes)?; // key: Hash(value), value: bits^-1(L(k, v))
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
    let left_hash = merklize_map(db, left)?;
    let right_hash = merklize_map(db, right)?;
    let branch = encode_branch(left_hash, right_hash);
    let branch_bytes = lsb_bits_to_bytes(branch.clone());
    let branch_hash = blake2b_256(&branch_bytes)?;
    store_node(db, &branch_hash, &branch_bytes)?;
    Ok(branch_hash)
}
// The basic Merklization function (`M_sigma`)
fn merklize_state(db: &dyn KeyValueDB, state: &GlobalState) -> Result<Hash32, MerklizationError> {
    let serialized_state = serialize_state(state);
    let mut state_map = HashMap::new();
    for (k, v) in serialized_state {
        state_map.insert(bytes_to_lsb_bits(k.to_vec()), (k, v));
    }
    merklize_map(db, state_map)
}

pub(crate) fn retrieve(
    db: &dyn KeyValueDB,
    root_hash: Hash32,
    merkle_path: BitVec,
) -> Result<Octets, MerklizationError> {
    let mut current_node_hash = root_hash;

    for bit in merkle_path {
        // If branch node, proceed. If leaf node, fetch the data
        if is_leaf(db, &current_node_hash)? {
            let data = get_data_from_leaf_hash(db, &current_node_hash)?;
            return Ok(data);
        }
        current_node_hash = get_child_hash(db, current_node_hash, !bit)?;
    }

    // Final node should be a leaf node
    if is_leaf(db, &current_node_hash)? {
        let data = get_data_from_leaf_hash(db, &current_node_hash)?;
        return Ok(data);
    }

    Err(MerklizationError::NodeNotFound)
}

fn get_child_hash(
    db: &dyn KeyValueDB,
    node_hash: Hash32,
    left: bool,
) -> Result<Hash32, MerklizationError> {
    // note: only branch node should call this
    let node_bytes = get_node(db, &node_hash)?;
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

fn is_leaf(db: &dyn KeyValueDB, node_hash: &Hash32) -> Result<bool, MerklizationError> {
    let node_bytes = get_node(db, node_hash)?;
    let node_bits = bytes_to_lsb_bits(node_bytes);

    Ok(node_bits[0])
}

fn get_data_from_leaf_hash(
    db: &dyn KeyValueDB,
    leaf_hash: &Hash32,
) -> Result<Octets, MerklizationError> {
    let node_bytes = get_node(db, leaf_hash)?;
    let node_bits = bytes_to_lsb_bits(node_bytes);
    let data_hash = bitvec_to_hash(slice_bitvec(&node_bits, 256..))?;
    get_node(db, &data_hash)
}
