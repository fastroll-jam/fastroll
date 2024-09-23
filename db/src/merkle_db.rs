use bit_vec::BitVec;
use lru::LruCache;
use rjam_codec::{JamCodecError, JamDecodeFixed};
use rjam_common::{Hash32, Octets, HASH32_EMPTY};
use rocksdb::{Options, DB};
use std::{collections::Bound, num::NonZeroUsize, ops::RangeBounds, ptr::hash, sync::Arc};
use thiserror::Error;

pub(crate) const NODE_SIZE_BITS: usize = 512;
const NODE_SIZE_BYTES: usize = NODE_SIZE_BITS / 8;
pub(crate) const EMPTY_HASH: Hash32 = [0u8; 32];

#[derive(Debug, Error)]
enum MerkleDBError {
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("Cache size must be larger than zero")]
    CacheSizeNonPositive,
    #[error("Invalid node type with hash")]
    InvalidNodeType,
    #[error("State not initialized")]
    EmptyState,
    #[error("Node codec error")]
    NodeCodecError,
    #[error("Node not found")]
    NodeNotFound,
    #[error("Merklization error: {0}")]
    MerklizationError(#[from] MerklizationError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Debug, Error)]
enum MerklizationError {
    #[error("Invalid byte length")]
    InvalidByteLength(usize),
    #[error("Invalid BitVec slice range")]
    InvalidBitVecSliceRange,
    #[error("Invalid node data length")]
    InvalidNodeDataLength(usize),
    #[error("Node merkle path doesn't match the encoded state key data in the node data")]
    NodeStateKeyMismatch,
    #[error("Invalid input for conversion to Hash32 type")]
    InvalidHash32Input,
    #[error("Invalid node type")]
    InvalidNodeType,
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// Branch node child type
enum ChildType {
    Left,
    Right,
}

/// Merkle trie node type
enum NodeType {
    Branch,
    Leaf(LeafType),
    Empty,
}

/// Leaf node type
enum LeafType {
    Embedded, // the encoded state data is not larger than 32 bytes
    Regular,  // other cases
}

#[derive(Clone)]
struct Node {
    hash: Hash32,
    data: Octets, // length must be 512 bits (64 bytes)
}

impl Node {
    /// Determines the type of the node based on its binary representation.
    ///
    /// The node type is encoded in the first two bits of the data:
    /// - Branch node:        [0xxxxxxx]
    /// - Embedded leaf node: [10xxxxxx]
    /// - Regular leaf node:  [11xxxxxx]
    ///
    /// Full node structures:
    /// - Branch node:        [0] + [255-bit left child hash] + [256-bit right child hash]
    /// - Embedded leaf node: [10] + [6-bit value length] + [248-bit state key] + [encoded state value] + [0 padding]
    /// - Regular leaf node:  [11] + [248-bit state key] + [256-bit hash of encoded state value]
    fn check_node_type(&self) -> Result<NodeType, MerkleDBError> {
        match (first_bit(&self.data), second_bit(&self.data)) {
            (Some(false), _) => Ok(NodeType::Branch),
            (Some(true), Some(false)) => Ok(NodeType::Leaf(LeafType::Embedded)),
            (Some(true), Some(true)) => Ok(NodeType::Leaf(LeafType::Regular)),
            _ => Err(MerkleDBError::InvalidNodeType),
        }
    }
}

/// Database and cache to store Merkle trie nodes
///
/// The nodes are stored in the database in the following format:
/// - [0-255 bit]:   [node hash]
/// TODO: add details
struct MerkleDB {
    db: Arc<DB>,
    cache: LruCache<Hash32, Node>,
    root: Hash32,
}

impl MerkleDB {
    pub fn new(db: Arc<DB>, cache_size: usize) -> Result<Self, MerkleDBError> {
        let cache_size =
            NonZeroUsize::new(cache_size).ok_or(MerkleDBError::CacheSizeNonPositive)?;

        Ok(Self {
            db,
            cache: LruCache::new(cache_size),
            root: HASH32_EMPTY,
        })
    }

    fn try_get_node_from_hash_bits(&mut self, bits: &BitVec) -> Result<Node, MerkleDBError> {
        match bits.len() {
            512 => {
                // For 512-bit input, construct Hash32 type and get the node
                let hash = bitvec_to_hash(bits)?;
                self.get_node(&hash)
            }
            511 => {
                // For 511-bit input, try both 0 and 1 as the first bit
                let mut full_bits = bits.clone();
                full_bits.insert(0, false); // try 0 bit

                let hash_0 = bitvec_to_hash(&full_bits)?;

                match self.get_node(&hash_0) {
                    Ok(node) => Ok(node),
                    Err(_) => {
                        full_bits.set(0, true);
                        let hash_1 = bitvec_to_hash(&full_bits)?;
                        self.get_node(&hash_1)
                    }
                }
            }
            _ => Err(MerklizationError::InvalidHash32Input.into()),
        }
    }

    fn get_node(&mut self, hash: &Hash32) -> Result<Node, MerkleDBError> {
        // lookup the cache
        if let Some(node) = self.cache.get(hash) {
            return Ok(node.clone());
        }

        // fetch node data octets from the db and put into the cache
        match self.db.get(hash) {
            Ok(Some(data)) => {
                let node = Node { hash: *hash, data };
                self.cache.put(*hash, node.clone());
                Ok(node)
            }
            Ok(None) => Err(MerkleDBError::NodeNotFound),
            Err(e) => Err(e.into()),
        }
    }

    fn put_node(&mut self, node: Node) -> Result<(), MerkleDBError> {
        self.cache.put(node.hash, node.clone());
        self.db.put(&node.hash, &node.data)?; // TODO: implement batch write mechanism
        Ok(())
    }

    /// Retrieves the data value of a leaf node, which represents the state data.
    ///
    /// - Embedded leaf node: Stores the encoded state data directly.
    /// - Regular leaf node: Stores the Blake2b-256 hash of the encoded state data.
    ///   This hash serves as a key for fetching the actual serialized state data from the StateDB.
    ///
    /// The serialized data in the StateDB has no size limit.
    ///
    /// # Arguments
    ///
    /// * `key`: A state key representing merkle path. The key work as merkle path to the leaf node that contains the state data.
    ///
    /// # Returns
    ///
    /// - `Ok(LeafType, Octets)`: The leaf node type and the Octets representing the state data
    ///    of type (Blake2b-256 hash or encoded state data) depending on the node type
    /// - `Err(MerkleDBError)`: Error occurred while retrieving the node data
    fn retrieve(&mut self, key: &[u8]) -> Result<(LeafType, Octets), MerkleDBError> {
        let key_bv = bytes_to_lsb_bits(key);
        let root_hash = self.root;
        let mut current_node = self.get_node(&root_hash)?; // initialize with the root node

        // `b` determines the next sub-trie to traverse (left or right)
        for b in &key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch => {
                    // update the current node and proceed to the next node
                    let child_type = if b { ChildType::Right } else { ChildType::Left };
                    let child_hash = get_child_hash_bits(&current_node.data, &child_type)?;
                    current_node = self.try_get_node_from_hash_bits(&child_hash)?;
                }
                NodeType::Leaf(leaf_type) => {
                    // extract the leaf value from the current node and return
                    let value = get_leaf_value(&key_bv, &current_node.data, &leaf_type)?;
                    return Ok((leaf_type, value));
                }
                NodeType::Empty => return Err(MerkleDBError::EmptyState),
            }
        }

        return Err(MerkleDBError::NodeNotFound);
    }
}

/// Extracts the hash identity of one of the two child nodes from a branch node data
///
/// This function takes the raw data of a branch node and returns the hash of the specified child
/// (left or right) in BitVec type. For the left child, it returns 511 bits (missing the first bit),
/// while for the right child, it returns the full 512 bits.
///
/// The returned bit vector allows for efficient prediction and confirmation of the left child's full hash
/// by trying both 0 and 1 for the missing first bit when retrieving the actual node.
///
/// `try_get_node_from_hash_bits` method of `MerkleDB` handles the both cases and fetch node with the hash bits key.
fn get_child_hash_bits(
    node_data: &[u8],
    child_type: &ChildType,
) -> Result<BitVec, MerklizationError> {
    // check node data length
    let len = node_data.len();
    if len != 64 {
        return Err(MerklizationError::InvalidNodeDataLength(len));
    }

    let bv = bytes_to_lsb_bits(node_data);
    let first_bit = bv.get(0).unwrap();

    // ensure the node data represents a branch node
    if first_bit {
        return Err(MerklizationError::InvalidNodeType);
    }

    match child_type {
        ChildType::Left => Ok(slice_bitvec(&bv, 1..=511)?),
        ChildType::Right => Ok(slice_bitvec(&bv, 512..)?),
    }
}

/// Extracts the state data from a leaf node data
///
/// This function takes the raw data and type (embedded or regular) of a leaf node and returns the JamCodec-encoded state data.
///
/// For regular leaf nodes, the leaf node data is the Blake2b-256 hash of the encoded state data.
/// For embedded leaf nodes, the leaf node data is the encoded state data itself.
fn get_leaf_value(
    state_key: &BitVec,
    node_data: &[u8],
    leaf_type: &LeafType,
) -> Result<Octets, MerklizationError> {
    // check node data length
    let len = node_data.len();
    if len != 64 {
        return Err(MerklizationError::InvalidNodeDataLength(len));
    }

    let bv = bytes_to_lsb_bits(node_data);
    let first_bit = bv.get(0).unwrap();

    // ensure the node data represents a leaf node
    if !first_bit {
        return Err(MerklizationError::InvalidNodeType);
    }

    // compare the state key with the encoded state key in the node data
    let key_without_last_byte = slice_bitvec(&bv, 8..256)?;
    let state_key_without_last_byte = slice_bitvec(state_key, 0..248)?;

    if key_without_last_byte != state_key_without_last_byte {
        return Err(MerklizationError::NodeStateKeyMismatch);
    }

    match leaf_type {
        LeafType::Embedded => Ok(slice_bitvec(&bv, 256..)?.to_bytes()),
        LeafType::Regular => {
            let value_len = slice_bitvec(&bv, 2..8)?.to_bytes();
            let value_len_in_bits = usize::decode_fixed(&mut &value_len[..], 1)? * 8;

            Ok(slice_bitvec(&bv, 256..value_len_in_bits)?.to_bytes())
        }
    }
}

//
// Util Functions
//

/// The `bits` function of the GP
fn bytes_to_lsb_bits(data: &[u8]) -> BitVec {
    let mut bits = BitVec::with_capacity(data.len() * 8);
    for &byte in data {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    bits
}

/// The inverse function of `bits` of the GP
fn lsb_bits_to_bytes(bits: &BitVec) -> Octets {
    let mut bytes = Vec::with_capacity((bits.len() + 7) / 8);
    let mut current_byte = 0u8;
    for (i, bit) in bits.iter().enumerate() {
        if bit {
            current_byte |= 1 << (i % 8);
        }
        if i % 8 == 7 {
            bytes.push(current_byte);
            current_byte = 0;
        }
    }
    // push remaining bits as the last byte
    if bits.len() % 8 != 0 {
        bytes.push(current_byte);
    }
    bytes
}

fn bitvec_to_hash(data: &BitVec) -> Result<Hash32, MerklizationError> {
    let bytes = lsb_bits_to_bytes(data);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| MerklizationError::InvalidByteLength(data.len()))
}

fn first_bit(data: &[u8]) -> Option<bool> {
    data.first().map(|&byte| (byte & 0b1000_0000) != 0)
}

fn second_bit(data: &[u8]) -> Option<bool> {
    data.first().map(|&byte| (byte & 0b0100_0000) != 0)
}

pub(crate) fn slice_bitvec<R>(bits: &BitVec, range: R) -> Result<BitVec, MerklizationError>
where
    R: RangeBounds<usize>,
{
    let start = match range.start_bound() {
        Bound::Included(&start) => start,
        Bound::Excluded(&start) => start + 1,
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&end) => end + 1,
        Bound::Excluded(&end) => end,
        Bound::Unbounded => bits.len(),
    };

    if start > bits.len() || end > bits.len() || end < start {
        return Err(MerklizationError::InvalidBitVecSliceRange);
    }

    Ok(bits
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect())
}
