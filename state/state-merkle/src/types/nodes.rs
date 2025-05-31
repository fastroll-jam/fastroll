use crate::{
    codec::NodeCodec, error::StateMerkleError, merkle_db::MerkleDB, write_set::MerkleNodeWrite,
};
use bit_vec::BitVec;
use fr_common::Hash32;
use fr_db::core::cached_db::CacheItem;
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
    /// - Embedded leaf node: [10] + [6-bit value length] + [248-bit state key] + [encoded state value] + [zero padding]
    /// - Regular leaf node:  [11] + [000000] + [248-bit state key] + [256-bit hash of encoded state value]
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
            node_hash: self.hash.clone(),
            left,
            right,
        })
    }

    /// Extracts 31-byte state key as a BitVec from the encoded leaf node data.
    pub fn extract_leaf_state_key_bv(&self) -> Result<BitVec, StateMerkleError> {
        match self.check_node_type()? {
            NodeType::Leaf(_) => Ok(self.parse_leaf()?.state_key_bv().clone()),
            _ => Err(StateMerkleError::InvalidNodeType),
        }
    }

    fn parse_leaf(&self) -> Result<LeafParsed, StateMerkleError> {
        match NodeCodec::decode_leaf(self)? {
            LeafParsed::EmbeddedLeaf(parsed) => Ok(LeafParsed::EmbeddedLeaf(EmbeddedLeafParsed {
                node_hash: self.hash.clone(),
                value: parsed.value,
                state_key_bv: parsed.state_key_bv,
            })),
            LeafParsed::RegularLeaf(parsed) => Ok(LeafParsed::RegularLeaf(RegularLeafParsed {
                node_hash: self.hash.clone(),
                val_hash: parsed.val_hash,
                state_key_bv: parsed.state_key_bv,
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

// --- Parsed Merkle Node Types (for debugging)

pub enum NodeDataParsed {
    Branch(BranchParsed),
    Leaf(LeafParsed),
}

impl Display for NodeDataParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Branch(branch) => write!(f, "{branch}"),
            Self::Leaf(leaf) => write!(f, "{leaf}"),
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
            Self::EmbeddedLeaf(leaf) => write!(f, "{leaf}"),
            Self::RegularLeaf(leaf) => write!(f, "{leaf}"),
        }
    }
}

impl LeafParsed {
    fn state_key_bv(&self) -> &BitVec {
        match self {
            Self::EmbeddedLeaf(leaf) => &leaf.state_key_bv,
            Self::RegularLeaf(leaf) => &leaf.state_key_bv,
        }
    }
}

#[derive(Debug)]
pub struct EmbeddedLeafParsed {
    /// Node hash identifier.
    pub node_hash: Hash32,
    /// Embedded raw state value.
    pub value: Vec<u8>,
    /// 248-bit state key of the entry that the leaf node represents.
    pub state_key_bv: BitVec,
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
            self.state_key_bv
        )
    }
}

#[derive(Debug)]
pub struct RegularLeafParsed {
    /// Node hash identifier.
    pub node_hash: Hash32,
    /// Hash of the state value. Used  as a key for the `StateDB` to retrieve the full encoded state value.
    pub val_hash: Hash32,
    /// 248-bit state key of the entry that the leaf node represents.
    pub state_key_bv: BitVec,
}

impl Display for RegularLeafParsed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Regular Leaf ({}) {{\n\
            \tval_hash: {},\n\
            \tState Key: 0b{},\n\
            }}",
            self.node_hash, self.val_hash, self.state_key_bv
        )
    }
}
