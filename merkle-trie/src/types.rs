use rjam_codec::JamCodecError;
use rjam_common::{Hash32, Octets};
use rjam_crypto::utils::CryptoError;
use thiserror::Error;

pub(crate) const NODE_SIZE_BITS: usize = 512;
pub(crate) const NODE_SIZE_BYTES: usize = NODE_SIZE_BITS / 8;
pub(crate) const EMPTY_HASH: Hash32 = [0u8; 32];

#[derive(Debug, Error)]
pub(crate) enum MerkleError {
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
    #[error("Invalid byte length")]
    InvalidByteLength(usize),
    #[error("Invalid BitVec slice range")]
    InvalidBitVecSliceRange,
    #[error("Invalid node data length")]
    InvalidNodeDataLength(usize),
    #[error("Invalid input for conversion to Hash32 type")]
    InvalidHash32Input,
    #[error("Write batch lock error")]
    WriteBatchLockError,
    #[error("RocksDB error: {0}")]
    RocksDBError(#[from] rocksdb::Error),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

//
// Node types
//

/// Merkle trie node type.
pub(crate) enum NodeType {
    Branch,
    Leaf(LeafType),
    Empty,
}

/// Leaf node type.
pub(crate) enum LeafType {
    /// Used for leaf nodes where the encoded state data is larger than 32 bytes.
    Embedded,
    /// Used for leaf nodes where the encoded state data length exceeds 32 bytes.
    Regular,
}

/// Branch node child type.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) enum ChildType {
    Left,
    Right,
}

impl ChildType {
    pub(crate) fn opposite(&self) -> Self {
        match self {
            ChildType::Left => ChildType::Right,
            ChildType::Right => ChildType::Left,
        }
    }
}

//
// Affected Node types
//

/// Leaf node write operations.
#[derive(Eq, Hash, PartialEq)]
pub(crate) enum WriteOp {
    Update(Hash32, Octets),
    Add(Hash32, Octets),
    Remove(Hash32),
}

/// Snapshot of the current state of the nodes to be affected by the state transition.
#[derive(Eq, Hash, PartialEq)]
pub(crate) enum AffectedNode {
    Branch(AffectedBranch),
    Leaf(AffectedLeaf),
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct AffectedBranch {
    /// Hash identifier of the current node.
    pub(crate) hash: Hash32,
    /// Depth of the current node in the trie.
    pub(crate) depth: u8,
    /// Hash of the left child. Used as a lookup key in the collection of `StagingNode`s.
    pub(crate) left: Hash32,
    /// Hash of the right child. Used as a lookup key in the collection of `StagingNode`s.
    pub(crate) right: Hash32,
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct AffectedLeaf {
    /// Depth of the current node in the trie.
    pub(crate) depth: u8,
    /// Context of the write operation.
    pub(crate) leaf_write_op_context: LeafWriteOpContext,
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) enum LeafWriteOpContext {
    Update(LeafUpdateContext),
    Add(LeafAddContext),
    Remove(LeafRemoveContext),
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct LeafUpdateContext {
    /// State key of the leaf node to be updated.
    pub(crate) leaf_state_key: Hash32,
    /// State value of the leaf node to be updated.
    pub(crate) leaf_state_value: Octets,
    /// Leaf hash prior to the update.
    pub(crate) leaf_prior_hash: Hash32,
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct LeafAddContext {
    /// State key of the leaf node to be added.
    pub(crate) leaf_state_key: Hash32,
    /// State value of the leaf node to be added.
    pub(crate) leaf_state_value: Octets,
    /// Hash of the leaf node to be the sibling node after adding a new leaf node.
    pub(crate) sibling_candidate_hash: Hash32,
    /// Child type (Left/Right) of the new leaf node.
    pub(crate) added_leaf_child_side: ChildType,
}

#[derive(Eq, Hash, PartialEq)]
pub(crate) struct LeafRemoveContext {
    /// Hash of the parent node of the leaf node to be removed.
    pub(crate) parent_hash: Hash32,
    /// Hash of the sibling node of the leaf node to be removed.
    pub(crate) sibling_hash: Hash32,
}
