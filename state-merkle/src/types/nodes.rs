use crate::{
    codec::NodeCodec, error::StateMerkleError, merkle_db::MerkleDB,
    types::write_context::LeafWriteOpContext, write_set::MerkleNodeWrite,
};
use bit_vec::BitVec;
use rjam_common::Hash32;
use rjam_db::core::cached_db::CacheItem;
use std::fmt::{Display, Formatter};

/// Merkle node data size in bits.
pub const NODE_SIZE_BITS: usize = 512;

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
    /// - Regular leaf node:  [11] + [000000] + [248-bit state key (partial)] + [256-bit hash of encoded state value]
    pub data: Vec<u8>,
}

impl From<MerkleNodeWrite> for MerkleNode {
    fn from(value: MerkleNodeWrite) -> Self {
        Self {
            hash: value.hash,
            data: value.node_data,
        }
    }
}

impl CacheItem for MerkleNode {
    fn into_db_value(self) -> Vec<u8> {
        self.data
    }

    fn from_db_kv(key: &[u8], val: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self {
            hash: Hash32::try_from(key).expect("Hash length mismatch"),
            data: val,
        }
    }
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

    async fn parse_branch(&self, merkle_db: &MerkleDB) -> Result<BranchParsed, StateMerkleError> {
        let (left, right) = NodeCodec::decode_branch(self, merkle_db).await?;

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
            NodeType::Leaf(_) => Ok(self.parse_leaf()?.partial_state_key().clone()),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }
    fn parse_leaf(&self) -> Result<LeafParsed, StateMerkleError> {
        match NodeCodec::decode_leaf(self)? {
            LeafParsed::EmbeddedLeaf(parsed) => Ok(LeafParsed::EmbeddedLeaf(EmbeddedLeafParsed {
                node_hash: self.hash,
                value: parsed.value,
                partial_state_key: parsed.partial_state_key,
            })),
            LeafParsed::RegularLeaf(parsed) => Ok(LeafParsed::RegularLeaf(RegularLeafParsed {
                node_hash: self.hash,
                value_hash: parsed.value_hash,
                partial_state_key: parsed.partial_state_key,
            })),
        }
    }

    pub async fn parse_node_data(
        &self,
        merkle_db: &MerkleDB,
    ) -> Result<NodeDataParsed, StateMerkleError> {
        match self.check_node_type()? {
            NodeType::Branch(_) => Ok(NodeDataParsed::Branch(self.parse_branch(merkle_db).await?)),
            NodeType::Leaf(_) => Ok(NodeDataParsed::Leaf(self.parse_leaf()?)),
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

    pub fn from_bit(bit: bool) -> Self {
        if bit {
            ChildType::Right
        } else {
            ChildType::Left
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

impl LeafParsed {
    fn partial_state_key(&self) -> &BitVec {
        match self {
            Self::EmbeddedLeaf(leaf) => &leaf.partial_state_key,
            Self::RegularLeaf(leaf) => &leaf.partial_state_key,
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
    PathNode(AffectedPathNode),
    Endpoint(AffectedEndpoint),
}

impl Display for AffectedNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AffectedNode::PathNode(branch) => write!(f, "AffectedNode::PathNode({})", branch),
            AffectedNode::Endpoint(leaf) => write!(f, "AffectedNode::Endpoint({})", leaf),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct AffectedPathNode {
    /// Hash identifier of the current node.
    pub hash: Hash32,
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Hash of the left child. Used as a lookup key in `MerkleDBWriteSet` (the collection of `MerkleNodeWrite`s).
    pub left: Hash32,
    /// Hash of the right child. Used as a lookup key in `MerkleDBWriteSet` (the collection of `MerkleNodeWrite`s).
    pub right: Hash32,
}

impl Display for AffectedPathNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AffectedPathNode {{ \
            \thash: {},\n\
            \tdepth: {},\n\
            \tleft: {},\n\
            \tright: {},\n\
            }}
            ",
            self.hash, self.depth, self.left, self.right,
        )
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub struct AffectedEndpoint {
    /// Hash identifier of the current node.
    pub hash: Hash32,
    /// Depth of the current node in the trie.
    pub depth: usize,
    /// Context of the write operation.
    pub leaf_write_op_context: LeafWriteOpContext,
}

impl Display for AffectedEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AffectedEndpoint {{ \n\
            \tdepth: {},\n\
            \tleaf_write_op_context: {}\n\
            }}",
            self.depth, self.leaf_write_op_context
        )
    }
}
