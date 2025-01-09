use crate::{codec::NodeCodec, error::StateMerkleError, merkle_db::MerkleDB};
use bit_vec::BitVec;
use rjam_common::Hash32;
use std::fmt::{Display, Formatter};

pub const NODE_SIZE_BITS: usize = 512;

//
// Merkle Node Types
//

/// Merkle trie node representation.
#[derive(Clone, Debug)]
pub struct MerkleNode {
    /// Identity of the node, which is Blake2b-256 hash of the `data` field.
    ///
    /// Used as key to node entry of the `MerkleDB`.
    pub hash: Hash32,
    /// 512-bit encoded node data.
    ///
    /// Represents a value stored in the `MerkleDB`.
    ///
    /// The node type is encoded in the first two bits of the `data` field.
    ///
    /// Full node structures:
    /// - Branch node:        [0]  + [255-bit left child hash (partial)] + [256-bit right child hash]
    /// - Embedded leaf node: [10] + [6-bit value length] + [248-bit state key (partial)] + [encoded state value] + [zero padding]
    /// - Regular leaf node:  [11] + [248-bit state key (partial)] + [256-bit hash of encoded state value]
    pub data: Vec<u8>,
}

impl MerkleNode {
    pub fn new(hash: Hash32, data: Vec<u8>) -> Self {
        Self { hash, data }
    }

    /// Determines the type of the node based on its binary representation.
    pub(crate) fn check_node_type(&self) -> Result<NodeType, StateMerkleError> {
        match (
            NodeCodec::first_bit(&self.data),
            NodeCodec::second_bit(&self.data),
        ) {
            (Some(false), _) => Ok(NodeType::Branch(self.check_branch_type()?)),
            (Some(true), Some(false)) => Ok(NodeType::Leaf(LeafType::Embedded)),
            (Some(true), Some(true)) => Ok(NodeType::Leaf(LeafType::Regular)),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    fn check_branch_type(&self) -> Result<BranchType, StateMerkleError> {
        NodeCodec::check_branch_type(self)
    }

    fn parse_branch(&self, merkle_db: &MerkleDB) -> Result<BranchParsed, StateMerkleError> {
        let (left, right) = NodeCodec::decode_branch(self, merkle_db)?;

        Ok(BranchParsed {
            node_hash: self.hash,
            left,
            right,
        })
    }

    /// Note: Since only the first 248 bits of the state key is encoded in the Leaf node data, we
    /// cannot recover the full state key by parsing the leaf node data.
    pub fn extract_partial_leaf_state_key(&self) -> Result<BitVec, StateMerkleError> {
        match self.check_node_type()? {
            NodeType::Leaf(LeafType::Embedded) => Ok(self.parse_embedded_leaf()?.partial_state_key),
            NodeType::Leaf(LeafType::Regular) => Ok(self.parse_regular_leaf()?.partial_state_key),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    // TODO: merge `parse_embedded_leaf` and `parse_regular_leaf`
    fn parse_embedded_leaf(&self) -> Result<EmbeddedLeafParsed, StateMerkleError> {
        match NodeCodec::decode_leaf(self)? {
            LeafParsed::EmbeddedLeaf(parsed) => Ok(EmbeddedLeafParsed {
                node_hash: self.hash,
                value: parsed.value,
                partial_state_key: parsed.partial_state_key,
            }),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    fn parse_regular_leaf(&self) -> Result<RegularLeafParsed, StateMerkleError> {
        match NodeCodec::decode_leaf(self)? {
            LeafParsed::RegularLeaf(parsed) => Ok(RegularLeafParsed {
                node_hash: self.hash,
                value_hash: parsed.value_hash,
                partial_state_key: parsed.partial_state_key,
            }),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    pub fn parse_node_data(
        &self,
        merkle_db: &MerkleDB,
    ) -> Result<NodeDataParsed, StateMerkleError> {
        match self.check_node_type()? {
            NodeType::Branch(_) => Ok(NodeDataParsed::Branch(self.parse_branch(merkle_db)?)),
            NodeType::Leaf(LeafType::Embedded) => Ok(NodeDataParsed::Leaf(
                LeafParsed::EmbeddedLeaf(self.parse_embedded_leaf()?),
            )),
            NodeType::Leaf(LeafType::Regular) => Ok(NodeDataParsed::Leaf(LeafParsed::RegularLeaf(
                self.parse_regular_leaf()?,
            ))),
        }
    }
}

/// Merkle trie node type.
#[derive(Debug)]
pub enum NodeType {
    Branch(BranchType),
    Leaf(LeafType),
}

/// Branch node type.
#[derive(Debug)]
pub enum BranchType {
    /// The branch has only the left child. Right child position is filled with an empty hash.
    LeftChildOnly,
    /// The branch has only the right child. Left child position is filled with an empty hash.
    RightChildOnly,
    /// The branch has two children nodes; left and right.
    Full,
}

impl BranchType {
    pub fn has_single_child(&self) -> bool {
        matches!(self, Self::RightChildOnly | Self::LeftChildOnly)
    }
}

/// Leaf node type.
#[derive(Debug)]
pub enum LeafType {
    /// Used for leaf nodes where the encoded state data is larger than 32 bytes.
    Embedded,
    /// Used for leaf nodes where the encoded state data length exceeds 32 bytes.
    Regular,
}

/// Branch node child type.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
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
// Parsed Merkle Node Types (for debugging)
//

pub enum NodeDataParsed {
    Branch(BranchParsed),
    Leaf(LeafParsed),
}

impl Display for NodeDataParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Branch(branch) => write!(f, "{}", branch),
            Self::Leaf(leaf) => write!(f, "{}", leaf),
        }
    }
}

#[derive(Debug)]
pub struct BranchParsed {
    /// Node hash identifier.
    pub node_hash: Hash32,
    /// Left child hash.
    pub left: Hash32,
    /// Right child hash.
    pub right: Hash32,
}

impl Display for BranchParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Branch ({}) {{\n\
            \tleft: {},\n\
            \tright: {}\n\
            }}",
            self.node_hash, self.left, self.right,
        )
    }
}

pub enum LeafParsed {
    EmbeddedLeaf(EmbeddedLeafParsed),
    RegularLeaf(RegularLeafParsed),
}

impl Display for LeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmbeddedLeaf(leaf) => write!(f, "{}", leaf),
            Self::RegularLeaf(leaf) => write!(f, "{}", leaf),
        }
    }
}

#[derive(Debug)]
pub struct EmbeddedLeafParsed {
    /// Node hash identifier.
    pub node_hash: Hash32,
    /// Embedded raw state value.
    pub value: Vec<u8>,
    /// 248-bit partial state key of the entry that the leaf node represents.
    pub partial_state_key: BitVec,
}

impl Display for EmbeddedLeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Embedded Leaf ({}) {{\n\
            \tvalue: 0x{},\n\
            \tState Key: 0b{},\n\
            }}",
            self.node_hash,
            hex::encode(&self.value),
            self.partial_state_key
        )
    }
}

#[derive(Debug)]
pub struct RegularLeafParsed {
    /// Node hash identifier.
    pub node_hash: Hash32,
    /// Hash of the state value. Used  as a key for the `StateDB` to retrieve the full encoded state value.
    pub value_hash: Hash32,
    /// 248-bit partial state key of the entry that the leaf node represents.
    pub partial_state_key: BitVec,
}

impl Display for RegularLeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Regular Leaf ({}) {{\n\
            \tvalue_hash: {},\n\
            \tState Key: 0b{},\n\
            }}",
            self.node_hash, self.value_hash, self.partial_state_key
        )
    }
}

//
// Affected Node Types
//

/// Leaf node write operations.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum MerkleWriteOp {
    Add(Hash32, Vec<u8>),    // (state_key, state_value)
    Update(Hash32, Vec<u8>), // (state_key, state_value)
    Remove(Hash32),          // state_key
}

/// Snapshot of the current state of the nodes to be affected by the state transition.
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum AffectedNode {
    Branch(AffectedBranch),
    Leaf(AffectedLeaf),
}

impl Display for AffectedNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AffectedNode::Branch(branch) => write!(f, "AffectedNode::Branch({})", branch),
            AffectedNode::Leaf(leaf) => write!(f, "AffectedNode::Leaf({})", leaf),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct AffectedBranch {
    /// Hash identifier of the current node.
    pub hash: Hash32,
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Hash of the left child. Used as a lookup key in `MerkleDBWriteSet` (the collection of `MerkleNodeWrite`s).
    pub left: Hash32,
    /// Hash of the right child. Used as a lookup key in `MerkleDBWriteSet` (the collection of `MerkleNodeWrite`s).
    pub right: Hash32,
    /// Context of the write operation. Only useful when a new leaf is being `Add`ed as a child of
    /// a single-child branch node, filling up the previously `EMPTY_HASH` side.
    pub leaf_write_op_context: Option<LeafWriteOpContext>,
}

impl Display for AffectedBranch {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ctx = match &self.leaf_write_op_context {
            Some(ctx) => format!("{}", ctx),
            None => String::new(),
        };

        write!(
            f,
            "AffectedBranch {{ \
            \thash: {},\n\
            \tdepth: {},\n\
            \tleft: {},\n\
            \tright: {},\n\
            \tleaf_write_op_context: {},\n\
            }}
            ",
            self.hash, self.depth, self.left, self.right, ctx
        )
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct AffectedLeaf {
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Context of the write operation.
    pub leaf_write_op_context: LeafWriteOpContext,
}

impl Display for AffectedLeaf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AffectedLeaf {{ \n\
            \tdepth: {},\n\
            \tleaf_write_op_context: {}\n\
            }}",
            self.depth, self.leaf_write_op_context
        )
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum LeafWriteOpContext {
    Update(LeafUpdateContext),
    Add(LeafAddContext),
    Remove(LeafRemoveContext),
}

impl Display for LeafWriteOpContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LeafWriteOpContext::Update(ctx) => write!(f, "Update({})", ctx),
            LeafWriteOpContext::Add(ctx) => write!(f, "Add({})", ctx),
            LeafWriteOpContext::Remove(ctx) => write!(f, "Remove({})", ctx),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct LeafUpdateContext {
    /// State key of the leaf node to be updated.
    pub leaf_state_key: Hash32,
    /// State value of the leaf node to be updated.
    pub leaf_state_value: Vec<u8>,
    /// Leaf hash prior to the update.
    pub leaf_prior_hash: Hash32,
}

impl Display for LeafUpdateContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LeafUpdateContext {{ \n\
            \tleaf_state_key: {},\n\
            \tleaf_state_value: 0x{},\n\
            \tleaf_prior_hash: {}\n\
            }}",
            self.leaf_state_key,
            hex::encode(&self.leaf_state_value),
            self.leaf_prior_hash
        )
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct LeafAddContext {
    /// State key of the leaf node to be added.
    pub leaf_state_key: Hash32,
    /// State value of the leaf node to be added.
    pub leaf_state_value: Vec<u8>,
    /// Hash of the leaf node to be the sibling node after adding a new leaf node.
    pub sibling_candidate_hash: Hash32,
    /// Child type (Left/Right) of the new leaf node.
    pub added_leaf_child_side: ChildType,
    /// Partial merkle path from the root to the `AffectedNode`.
    /// Used for handling path compression at leaf node.
    pub partial_merkle_path: Option<BitVec>,
    /// Partial 248-bit state key of the sibling candidate leaf node, which is parsed from its node data.
    /// Used for handling path compression at leaf node.
    pub sibling_partial_state_key: Option<BitVec>,
}

impl Display for LeafAddContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LeafAddContext {{ \n\
            \tleaf_state_key: {},\n\
            \tleaf_state_value: 0x{},\n\
            \tsibling_candidate_hash: {},\n\
            \tadded_leaf_child_side: {:?}\n\
            }}",
            self.leaf_state_key,
            hex::encode(&self.leaf_state_value),
            self.sibling_candidate_hash,
            self.added_leaf_child_side
        )
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct LeafRemoveContext {
    /// Hash of the parent node of the leaf node to be removed.
    pub parent_hash: Hash32,
    /// Hash of the sibling node of the leaf node to be removed.
    pub sibling_hash: Hash32,
}

impl Display for LeafRemoveContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LeafRemoveContext {{ \n\
            \tparent_hash: {},\n\
            \tsibling_hash: {}\n\
            }}",
            self.parent_hash, self.sibling_hash
        )
    }
}
