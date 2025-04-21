use crate::types::nodes::ChildType;
use bit_vec::BitVec;
use rjam_common::Hash32;
use std::fmt::{Display, Formatter};

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

/// Context required for splitting a leaf for the addition and further decompressing the merkle path.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LeafSplitContext {
    /// Partial merkle path from the root to the `AffectedNode`.
    /// Used for handling path compression at leaf node.
    pub partial_merkle_path: BitVec,
    /// Partial 248-bit state key of the sibling candidate leaf node, which is parsed from its node data.
    /// Used for handling path compression at leaf node.
    pub sibling_state_key_248: BitVec,
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
    /// Context required for the leaf-splitting case.
    pub leaf_split_context: Option<LeafSplitContext>,
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
            \tleaf_split_context: {:?}\n\
            }}",
            self.leaf_state_key,
            hex::encode(&self.leaf_state_value),
            self.sibling_candidate_hash,
            self.added_leaf_child_side,
            self.leaf_split_context,
        )
    }
}

impl LeafAddContext {
    pub fn is_splitting_leaf(&self) -> bool {
        self.leaf_split_context.is_some()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct LeafRemoveContext {
    /// Hash of the node that will be the "deepest" affected node for the removal.
    pub post_parent_hash: Hash32,
    /// Left child hash of `post_parent_hash` branch node prior to the removal.
    pub prior_left: Hash32,
    /// Right child hash of `post_parent_hash` branch node prior to the removal.
    pub prior_right: Hash32,
    /// Only needed when the sibling of the remove target node is leaf type.
    pub sibling_leaf_hash: Option<Hash32>,
    /// Whether left or right subtrie of the `post_parent_hash` is getting compressed or deleted after the removal.
    pub removal_side: ChildType,
}

impl Display for LeafRemoveContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let sibling_leaf_hash = match self.sibling_leaf_hash {
            Some(hash) => format!("{}", hash),
            None => String::from("None"),
        };
        write!(
            f,
            "LeafRemoveContext {{ \n\
            \tpost_parent_hash: {},\n\
            \tprior_left: {},\n\
            \tprior_right: {},\n\
            \tsibling_leaf_hash: {},\n\
            \tremoval_side: {:?},\n\
            }}",
            self.post_parent_hash,
            self.prior_left,
            self.prior_right,
            sibling_leaf_hash,
            self.removal_side
        )
    }
}

impl LeafRemoveContext {
    pub fn has_sibling_leaf(&self) -> bool {
        self.sibling_leaf_hash.is_some()
    }
}

pub(crate) struct FullBranchSnapshot {
    pub(crate) hash: Hash32,
    pub(crate) navigate_to: ChildType,
    pub(crate) left_child: Hash32,
    pub(crate) right_child: Hash32,
}

pub(crate) struct FullBranchHistory {
    pub(crate) curr: FullBranchSnapshot,
    pub(crate) prev: FullBranchSnapshot,
}

impl FullBranchHistory {
    pub(crate) fn new(
        root: Hash32,
        first_bit: bool,
        left_child: Hash32,
        right_child: Hash32,
    ) -> Self {
        Self {
            curr: FullBranchSnapshot {
                hash: root,
                navigate_to: ChildType::from_bit(first_bit),
                left_child,
                right_child,
            },
            prev: FullBranchSnapshot {
                hash: root,
                navigate_to: ChildType::from_bit(first_bit),
                left_child,
                right_child,
            },
        }
    }

    /// Update the `prev` snapshot to be what the `curr` was, and then set `curr` to a new snapshot.
    pub(crate) fn update(&mut self, node_hash: Hash32, bit: bool, left: Hash32, right: Hash32) {
        // shift `curr` into `prev`
        self.prev.hash = self.curr.hash;
        self.prev.navigate_to = self.curr.navigate_to;
        self.prev.left_child = self.curr.left_child;
        self.prev.right_child = self.curr.right_child;

        // set up `curr`
        self.curr.hash = node_hash;
        self.curr.navigate_to = ChildType::from_bit(bit);
        self.curr.left_child = left;
        self.curr.right_child = right;
    }
}
