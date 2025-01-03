use crate::{
    codec::NodeCodec,
    error::StateMerkleError,
    utils::{bits_encode_msb, bitvec_to_hash32},
};
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_crypto::octets_to_hash32;
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
            (Some(false), _) => Ok(NodeType::Branch),
            (Some(true), Some(false)) => Ok(NodeType::Leaf(LeafType::Embedded)),
            (Some(true), Some(true)) => Ok(NodeType::Leaf(LeafType::Regular)),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    fn parse_branch(&self) -> Result<BranchParsed, StateMerkleError> {
        let left_child_bv = NodeCodec::get_child_hash_bits(&self.data, &ChildType::Left)?; // 255 bits (1 bit missing)
        let right_child_bv = NodeCodec::get_child_hash_bits(&self.data, &ChildType::Right)?; // 256 bits (full-length Hash32 representation)

        Ok(BranchParsed {
            node_hash: self.hash,
            left_child: bitvec_to_hash32(&left_child_bv)?, // FIXME: return the restored left child hash
            right_child: bitvec_to_hash32(&right_child_bv)?,
        })
    }

    fn parse_embedded_leaf(&self) -> Result<EmbeddedLeafParsed, StateMerkleError> {
        let node_data_bv = bits_encode_msb(&self.data);
        let embedded_data = NodeCodec::decode_leaf(&node_data_bv, &LeafType::Embedded)?;

        Ok(EmbeddedLeafParsed {
            node_hash: self.hash,
            value: embedded_data,
        })
    }

    fn parse_regular_leaf(&self) -> Result<RegularLeafParsed, StateMerkleError> {
        let node_data_bv = bits_encode_msb(&self.data);
        let state_data_hash = NodeCodec::decode_leaf(&node_data_bv, &LeafType::Regular)?;

        Ok(RegularLeafParsed {
            node_hash: self.hash,
            value_hash: octets_to_hash32(&state_data_hash)
                .ok_or(StateMerkleError::InvalidHash32Input)?,
        })
    }

    pub fn parse_node_data(&self) -> Result<NodeDataParsed, StateMerkleError> {
        match self.check_node_type()? {
            NodeType::Branch => Ok(NodeDataParsed::Branch(self.parse_branch()?)),
            NodeType::Leaf(LeafType::Embedded) => {
                Ok(NodeDataParsed::EmbeddedLeaf(self.parse_embedded_leaf()?))
            }
            NodeType::Leaf(LeafType::Regular) => {
                Ok(NodeDataParsed::RegularLeaf(self.parse_regular_leaf()?))
            }
            NodeType::Empty => Ok(NodeDataParsed::Empty(HASH32_EMPTY)),
        }
    }
}

/// Merkle trie node type.
#[derive(Debug)]
pub enum NodeType {
    Branch,
    Leaf(LeafType),
    Empty,
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
// Parsed Merkle Node Types (for debugging)
//

pub enum NodeDataParsed {
    Branch(BranchParsed),
    EmbeddedLeaf(EmbeddedLeafParsed),
    RegularLeaf(RegularLeafParsed),
    Empty(Hash32), // HASH32_EMPTY
}

impl Display for NodeDataParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Branch(branch) => write!(f, "{}", branch),
            Self::EmbeddedLeaf(leaf) => write!(f, "{}", leaf),
            Self::RegularLeaf(leaf) => write!(f, "{}", leaf),
            Self::Empty(hash) => write!(f, "Empty({})", hash),
        }
    }
}

#[derive(Debug)]
pub struct BranchParsed {
    pub node_hash: Hash32, // Node hash identifier
    pub left_child: Hash32,
    pub right_child: Hash32,
}

impl Display for BranchParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Branch ({}) {{\n\
            \tleft: {},\n\
            \tright: {}\n\
            }}",
            self.node_hash, self.left_child, self.right_child,
        )
    }
}

#[derive(Debug)]
pub struct EmbeddedLeafParsed {
    pub node_hash: Hash32, // Node hash identifier
    pub value: Vec<u8>,
}

impl Display for EmbeddedLeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Embedded Leaf ({}) {{\n\
            \tvalue: 0x{},\n\
            }}",
            self.node_hash,
            hex::encode(&self.value),
        )
    }
}

#[derive(Debug)]
pub struct RegularLeafParsed {
    pub node_hash: Hash32,  // Node hash identifier
    pub value_hash: Hash32, // Used as a key for the `StateDB` to retrieve the full encoded state value.
}

impl Display for RegularLeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Regular Leaf ({}) {{\n\
            \tvalue_hash: {},\n\
            }}",
            self.node_hash, self.value_hash
        )
    }
}

//
// Affected Node Types
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
