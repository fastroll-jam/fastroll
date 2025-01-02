use rjam_common::Hash32;

pub const NODE_SIZE_BITS: usize = 512;

/// Merkle trie node type.
pub enum NodeType {
    Branch,
    Leaf(LeafType),
    Empty,
}

/// Leaf node type.
pub enum LeafType {
    /// Used for leaf nodes where the encoded state data is larger than 32 bytes.
    Embedded,
    /// Used for leaf nodes where the encoded state data length exceeds 32 bytes.
    Regular,
}

/// Branch node child type.
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub enum ChildType {
    Left,
    Right,
}

impl ChildType {
    pub fn opposite(&self) -> Self {
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
#[derive(Hash, PartialEq, Eq)]
pub enum MerkleWriteOp {
    Add(Hash32, Vec<u8>),    // (state_key, state_value)
    Update(Hash32, Vec<u8>), // (state_key, state_value)
    Remove(Hash32),          // state_key
}

/// Snapshot of the current state of the nodes to be affected by the state transition.
#[derive(Hash, PartialEq, Eq)]
pub enum AffectedNode {
    Branch(AffectedBranch),
    Leaf(AffectedLeaf),
}

#[derive(Hash, PartialEq, Eq)]
pub struct AffectedBranch {
    /// Hash identifier of the current node.
    pub hash: Hash32,
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Hash of the left child. Used as a lookup key in the collection of `StagingMerkleNode`s.
    pub left: Hash32,
    /// Hash of the right child. Used as a lookup key in the collection of `StagingMerkleNode`s.
    pub right: Hash32,
}

#[derive(Hash, PartialEq, Eq)]
pub struct AffectedLeaf {
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Context of the write operation.
    pub leaf_write_op_context: LeafWriteOpContext,
}

#[derive(Hash, PartialEq, Eq)]
pub enum LeafWriteOpContext {
    Update(LeafUpdateContext),
    Add(LeafAddContext),
    Remove(LeafRemoveContext),
}

#[derive(Hash, PartialEq, Eq)]
pub struct LeafUpdateContext {
    /// State key of the leaf node to be updated.
    pub leaf_state_key: Hash32,
    /// State value of the leaf node to be updated.
    pub leaf_state_value: Vec<u8>,
    /// Leaf hash prior to the update.
    pub leaf_prior_hash: Hash32,
}

#[derive(Hash, PartialEq, Eq)]
pub struct LeafAddContext {
    /// State key of the leaf node to be added.
    pub leaf_state_key: Hash32,
    /// State value of the leaf node to be added.
    pub leaf_state_value: Vec<u8>,
    /// Hash of the leaf node to be the sibling node after adding a new leaf node.
    pub sibling_candidate_hash: Hash32,
    /// Child type (Left/Right) of the new leaf node.
    pub added_leaf_child_side: ChildType,
}

#[derive(Hash, PartialEq, Eq)]
pub struct LeafRemoveContext {
    /// Hash of the parent node of the leaf node to be removed.
    pub parent_hash: Hash32,
    /// Hash of the sibling node of the leaf node to be removed.
    pub sibling_hash: Hash32,
}
