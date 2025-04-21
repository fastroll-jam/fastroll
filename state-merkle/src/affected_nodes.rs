use crate::{
    codec::NodeCodec,
    error::StateMerkleError,
    types::{
        nodes::ChildType,
        write_context::{LeafAddContext, LeafRemoveContext, LeafUpdateContext, LeafWriteOpContext},
    },
    utils::bits_encode_msb,
    write_set::{DBWriteSet, MerkleDBWriteSet, MerkleNodeWrite, StateDBWriteSet},
};
use bit_vec::BitVec;
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
};

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

/// Collection of merkle trie nodes affected by state write operations.
///
/// * Key: Depth of the node in the trie.
/// * Value: `AffectedNode`, which contains necessary contexts for updating the trie.
#[derive(Debug, Default)]
pub(crate) struct AffectedNodesByDepth {
    inner: BTreeMap<usize, AffectedNode>,
}

impl Deref for AffectedNodesByDepth {
    type Target = BTreeMap<usize, AffectedNode>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AffectedNodesByDepth {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Display for AffectedNodesByDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.inner.is_empty() {
            return writeln!(f, "AffectedNodesByDepth is empty");
        }

        for (depth, affected_node) in &self.inner {
            writeln!(f, "Depth: {depth}, Affected Node: {affected_node}")?;
        }
        Ok(())
    }
}

impl AffectedNodesByDepth {
    /// Converts a collection of `AffectedNode`s into a `DBWriteSet`
    /// for committing changes to the `MerkleDB` and `StateDB`.
    pub(crate) fn into_merkle_write_set(self) -> Result<DBWriteSet, StateMerkleError> {
        if self.is_empty() {
            return Ok(DBWriteSet::default());
        }

        let mut merkle_db_write_set = MerkleDBWriteSet::default();
        let mut state_db_write_set = StateDBWriteSet::default();

        let mut iter_rev = self.iter().rev().peekable();
        while let Some((_depth, affected_node)) = iter_rev.next() {
            // The final iteration will handle the root node (reverse iteration starting from the leaf).
            let is_root_node = iter_rev.peek().is_none();

            let maybe_new_root = Self::process_affected_node(
                affected_node,
                &mut merkle_db_write_set,
                &mut state_db_write_set,
                is_root_node,
            )?;
            if let Some(new_root) = maybe_new_root {
                // Contain the new root hash to the `MerkleDBWriteSet` struct.
                merkle_db_write_set.set_new_root(new_root);
            }
        }

        Ok(DBWriteSet::new(merkle_db_write_set, state_db_write_set))
    }

    fn process_affected_node(
        affected_node: &AffectedNode,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        state_db_write_set: &mut StateDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        let maybe_root = match affected_node {
            AffectedNode::PathNode(path_node) => {
                Self::process_affected_path_node(path_node, merkle_db_write_set, is_root_node)?
            }
            AffectedNode::Endpoint(endpoint) => match &endpoint.leaf_write_op_context {
                LeafWriteOpContext::Add(ctx) => Self::process_add_affected_endpoint(
                    endpoint,
                    ctx,
                    state_db_write_set,
                    merkle_db_write_set,
                    is_root_node,
                )?,
                LeafWriteOpContext::Update(ctx) => Self::process_update_affected_endpoint(
                    ctx,
                    state_db_write_set,
                    merkle_db_write_set,
                    is_root_node,
                )?,
                LeafWriteOpContext::Remove(ctx) => {
                    Self::process_remove_affected_endpoint(ctx, merkle_db_write_set, is_root_node)?
                }
            },
        };

        Ok(maybe_root)
    }

    /// `PathNode` is always a branch node. With the potentially updated child nodes,
    /// encode a new branch node and put it into `merkle_db_write_set`.
    fn process_affected_path_node(
        path_node: &AffectedPathNode,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        let prior_hash = path_node.hash;

        // Lookup `merkle_db_write_set` to check which side of its child hash
        // was affected in the 1-level deeper depth.
        // If the child hash was not affected, use its original hash.
        // For some branch nodes, both the left and right child might be affected.
        let left_hash = merkle_db_write_set
            .get(&path_node.left)
            .map_or(path_node.left, |left_updated| left_updated.hash);
        let right_hash = merkle_db_write_set
            .get(&path_node.right)
            .map_or(path_node.right, |right_updated| right_updated.hash);

        // Updated branch node data after the partial merkle write.
        let node_data = NodeCodec::encode_branch(&left_hash, &right_hash)?;
        let node_hash = hash::<Blake2b256>(&node_data)?;

        let merkle_write = MerkleNodeWrite::new(node_hash, node_data);
        merkle_db_write_set.insert(prior_hash, merkle_write);

        if is_root_node {
            Ok(Some(node_hash))
        } else {
            Ok(None)
        }
    }

    /// Endpoint `AffectedNode` for `Add` operation can be either a leaf node or
    /// a single-child branch, which will be a future sibling leaf of the new leaf
    /// being added.
    ///
    /// ### Case 1: Endpoint `AffectedNode` is a leaf node.
    /// In this case, the endpoint must be "split", decompressing the merkle path
    /// which was compressed under the endpoint leaf node.
    /// If the newly added leaf node and its future sibling leaf share `N` more
    /// common merkle path bits from the endpoint leaf node's original position,
    /// (`N` + 2) new entries will be added into the `MerkleDB`:
    ///
    /// One for the new leaf that holds the new state data,
    /// one for the new branch node which will be a parent of the new leaf and
    /// its sibling, and `N` more single-child branches to represent the decompressed
    /// path.
    ///
    ///
    /// ### Case 2: Endpoint `AffectedNode` is a single-child branch.
    /// In this case, two new entries will be added into the `MerkleDB`:
    ///
    /// One for the new leaf that holds the new state data,
    /// and the other for the new branch node that will replace the position of
    /// the endpoint `AffectedNode`, pointing the new leaf node and its sibling
    /// node as children.
    fn process_add_affected_endpoint(
        endpoint: &AffectedEndpoint,
        ctx: &LeafAddContext,
        state_db_write_set: &mut StateDBWriteSet,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        // Create a new leaf node as a merkle write.
        let state_value_slice = ctx.leaf_state_value.as_slice();
        let added_leaf_node_data = NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

        state_db_write_set.insert_if_regular_leaf(state_value_slice)?;

        let added_leaf_node_hash = hash::<Blake2b256>(&added_leaf_node_data)?;
        let added_leaf_write = MerkleNodeWrite::new(added_leaf_node_hash, added_leaf_node_data);

        // Create a new branch node as a merkle write. This branch has the
        // new leaf node and its sibling candidate node as its children.

        let (new_branch_left_hash, new_branch_right_hash) = match ctx.added_leaf_child_side {
            ChildType::Left => (added_leaf_node_hash, ctx.sibling_candidate_hash),
            ChildType::Right => (ctx.sibling_candidate_hash, added_leaf_node_hash),
        };

        let new_branch_node_data =
            NodeCodec::encode_branch(&new_branch_left_hash, &new_branch_right_hash)?;
        let new_branch_node_hash = hash::<Blake2b256>(&new_branch_node_data)?;
        let new_branch_merkle_write =
            MerkleNodeWrite::new(new_branch_node_hash, new_branch_node_data);

        if ctx.is_splitting_leaf() {
            // Case 1: affected node endpoint is leaf
            // Path decompression handling
            let leaf_split_ctx = ctx
                .leaf_split_context
                .clone()
                .expect("leaf split context should be provided here");
            let new_leaf_state_key = ctx.leaf_state_key;
            let common_path_to_decompress = Self::get_common_path(
                &leaf_split_ctx.partial_merkle_path,
                &new_leaf_state_key,
                &leaf_split_ctx.sibling_state_key_248,
            )?;
            let decompression_write_set = Self::generate_decompression_set(
                common_path_to_decompress,
                &ctx.sibling_candidate_hash,
                added_leaf_write,
                new_branch_merkle_write,
            )?;
            let (_, top_level_merkle_write) = decompression_write_set
                .last()
                .cloned()
                .expect("decompression set cannot be empty");

            // Insert merkle db write set entries
            for (merkle_write_lookup_key, write) in decompression_write_set {
                merkle_db_write_set.insert(merkle_write_lookup_key, write);
            }
            // Calculate the new root hash.
            // Note: This case is relevant only for the case when the affected leaf node
            // "was" the only node in the trie, therefore being a merkle root, and then
            // a new leaf is added. This is the only case when the merkle root node is
            // changed from a leaf node into a branch node.
            if is_root_node {
                Ok(Some(top_level_merkle_write.hash))
            } else {
                Ok(None)
            }
        } else {
            // Case 2: affected node endpoint is single-child branch
            merkle_db_write_set.insert(added_leaf_node_hash, added_leaf_write); // note: `new_leaf_node_hash`, key of this entry will not be used as a lookup key.
            merkle_db_write_set.insert(endpoint.hash, new_branch_merkle_write);

            if is_root_node {
                Ok(Some(new_branch_node_hash))
            } else {
                Ok(None)
            }
        }
    }

    /// Endpoint `AffectedNode` for `Update` operation is always a leaf node, which represents
    /// the target state to be updated.
    ///
    /// In this case, only one new entry is added into the `MerkleDB`: The new leaf node.
    fn process_update_affected_endpoint(
        ctx: &LeafUpdateContext,
        state_db_write_set: &mut StateDBWriteSet,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        // the leaf node data after the state transition
        let state_value_slice = ctx.leaf_state_value.as_slice();
        let node_data = NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

        state_db_write_set.insert_if_regular_leaf(state_value_slice)?;

        let hash = hash::<Blake2b256>(&node_data)?;
        let merkle_write = MerkleNodeWrite::new(hash, node_data);

        merkle_db_write_set.insert(ctx.leaf_prior_hash, merkle_write);
        if is_root_node {
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    /// Endpoint `AffectedNode` for `Remove` operation is always a full-branch node.
    ///
    /// In thie case, only one new entry is added into the `MerkleDB`.
    ///
    /// However, the merkle trie update behavior is different by the node type of the sibling
    /// of the removing node.
    ///
    /// If the sibling is a branch, the endpoint becomes a single-child branch after the removal.
    /// If the sibling is a leaf, the endpoint becomes a full-branch with some potential merkle path
    /// compression.
    fn process_remove_affected_endpoint(
        ctx: &LeafRemoveContext,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        // This case compresses path bits to the leaf node.
        let mut left = ctx.prior_left;
        let mut right = ctx.prior_right;
        if ctx.has_sibling_leaf() {
            // Sibling of the leaf being removed is leaf node
            match ctx.removal_side {
                ChildType::Left => {
                    left = ctx.sibling_leaf_hash.expect("should not be None");
                }
                ChildType::Right => {
                    right = ctx.sibling_leaf_hash.expect("should not be None");
                }
            };
        } else {
            // Sibling of the leaf being removed is branch node
            match ctx.removal_side {
                ChildType::Left => left = Hash32::default(),
                ChildType::Right => right = Hash32::default(),
            }
        }

        let post_parent_data = NodeCodec::encode_branch(&left, &right)?;
        let post_parent_data_new_hash = hash::<Blake2b256>(&post_parent_data)?;
        merkle_db_write_set.insert(
            ctx.post_parent_hash,
            MerkleNodeWrite::new(post_parent_data_new_hash, post_parent_data),
        );

        if is_root_node {
            Ok(Some(post_parent_data_new_hash))
        } else {
            Ok(None)
        }
    }

    fn get_common_path(
        partial_merkle_path: &BitVec,
        new_leaf_state_key: &Hash32,
        sibling_state_key_248: &BitVec,
    ) -> Result<BitVec, StateMerkleError> {
        let new_leaf_state_key = bits_encode_msb(new_leaf_state_key.as_slice());

        // Validate inputs
        let partial_len = partial_merkle_path.len();
        if partial_len > new_leaf_state_key.len() || partial_len > sibling_state_key_248.len() {
            return Err(StateMerkleError::InvalidMerklePath);
        }

        for i in 0..partial_len {
            let bit = partial_merkle_path[i];
            if new_leaf_state_key[i] != bit || sibling_state_key_248[i] != bit {
                return Err(StateMerkleError::InvalidMerklePath);
            }
        }

        // Check how many bits the new leaf state key and its sibling leaf state key have in common
        // after the `partial_merkle_path`.
        // Here, we can only compare the first 248 bits of the state key, since that is what we can
        // restore from the encoded sibling leaf node data.
        let mut common_path_to_decompress = BitVec::new();
        for (new_leaf_bit, sibling_leaf_bit) in new_leaf_state_key
            .iter()
            .skip(partial_len)
            .zip(sibling_state_key_248.iter().skip(partial_len))
        {
            if new_leaf_bit == sibling_leaf_bit {
                common_path_to_decompress.push(new_leaf_bit)
            } else {
                break;
            }
        }

        Ok(common_path_to_decompress)
    }

    /// Generates `MerkleNodeWrite` entries for single-child branch nodes that are required for
    /// decompressing the merkle path and placing the added leaf node and its sibling leaf node
    /// properly.
    ///
    /// Returns `Vec<(Hash32, MerkleNodeWrite)>`, where the `Hash32` is used as a key in `MerkleDBWriteSet` map.
    /// The vector must be ordered bottom-up, so the last entry will represent the node at the top level.
    fn generate_decompression_set(
        common_path_to_decompress: BitVec,
        sibling_hash: &Hash32,
        new_leaf_write: MerkleNodeWrite,
        new_branch_write: MerkleNodeWrite,
    ) -> Result<Vec<(Hash32, MerkleNodeWrite)>, StateMerkleError> {
        // If there is no further common path, produces two `MerkleNodeWrite`s:
        // one for the new leaf and another for the new branch.
        if common_path_to_decompress.is_empty() {
            return Ok(vec![
                (new_leaf_write.hash, new_leaf_write),
                (*sibling_hash, new_branch_write),
            ]);
        }

        // Bottom-up approach
        let mut child_hash = new_branch_write.hash;
        let mut path_iter_rev = common_path_to_decompress.iter().rev().peekable();

        // If the common path length is `N` bits, produces `N` more single-child branches to mark
        // the decompressed merkle path. The single-child branch at the top must be indexed with
        // the sibling leaf hash.
        let mut result = vec![
            (new_leaf_write.hash, new_leaf_write),
            (new_branch_write.hash, new_branch_write),
        ];

        // `b` refers to the child side
        while let Some(b) = path_iter_rev.next() {
            let is_top_branch = path_iter_rev.peek().is_none();
            let (left_child, right_child) = if b {
                (Hash32::default(), child_hash)
            } else {
                (child_hash, Hash32::default())
            };
            let single_child_branch_data = NodeCodec::encode_branch(&left_child, &right_child)?;
            let single_child_branch_hash = hash::<Blake2b256>(&single_child_branch_data)?;

            let merkle_write_lookup_key = if is_top_branch {
                *sibling_hash
            } else {
                single_child_branch_hash
            };

            result.push((
                merkle_write_lookup_key,
                MerkleNodeWrite::new(single_child_branch_hash, single_child_branch_data),
            ));

            child_hash = single_child_branch_hash;
        }

        Ok(result)
    }
}
