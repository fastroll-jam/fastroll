use crate::{codec::NodeCodec, error::StateMerkleError, types::*};
use rjam_common::Hash32;
use rjam_crypto::{hash, Blake2b256};
use rocksdb::WriteBatch;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::{Deref, DerefMut},
};

/// Staging node struct to be added to `WriteBatch` of the `MerkleDB`.
pub struct StagingMerkleNode {
    /// Blake2b-256 hash of the `node_data` field.
    /// Used as a key to a new entry to be added in the `MerkleDB`.
    hash: Hash32,
    /// Encoded node data after state transition.
    /// Data of the new entry to be added in the `MerkleDB`.
    node_data: Vec<u8>,
}

impl StagingMerkleNode {
    pub fn new(hash: Hash32, node_data: Vec<u8>) -> Self {
        Self { hash, node_data }
    }
}

#[derive(Default)]
pub struct StagingSet {
    inner: HashMap<Hash32, StagingMerkleNode>,
}

impl Deref for StagingSet {
    type Target = HashMap<Hash32, StagingMerkleNode>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StagingSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl StagingSet {
    pub fn new(inner: HashMap<Hash32, StagingMerkleNode>) -> Self {
        Self { inner }
    }

    /// Generates `WriteBatch` from `staging_set`, simply converting `StagingMerkleNode`s into `MerkleDB` entries.
    pub fn generate_write_batch(&self) -> Result<WriteBatch, StateMerkleError> {
        let mut batch = WriteBatch::default();
        // `MerkleDB` entry format: (key: Hash32(value), value: encoded node value)
        self.values().for_each(|node| {
            batch.put(node.hash.as_slice(), &node.node_data);
        });

        Ok(batch)
    }
}

#[derive(Default)]
pub struct AffectedNodesByDepth {
    inner: BTreeMap<usize, HashSet<AffectedNode>>,
}

impl Deref for AffectedNodesByDepth {
    type Target = BTreeMap<usize, HashSet<AffectedNode>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for AffectedNodesByDepth {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AffectedNodesByDepth {
    pub fn new(inner: BTreeMap<usize, HashSet<AffectedNode>>) -> Self {
        Self { inner }
    }

    /// Generates a collection of `StagingMerkleNode`s from `AffectedNode`s.
    ///
    /// # Purpose
    /// This function is crucial for:
    /// * Transforming affected nodes into staging nodes ready for database (`MerkleDB`) insertion.
    /// * Maintaining the integrity of the Merkle trie during updates.
    /// * Preparing the final state of nodes after all write operations are applied.
    ///
    /// # Process
    /// - Iterates through affected nodes bottom-up (from leaves to root).
    /// - For each node:
    ///   - `Branch` nodes: Updates child hashes based on previous iterations.
    ///   - `Leaf` nodes: Handles updates, additions, and removals differently.
    /// - Creates new `StagingMerkleNode`s with updated data and hashes.
    ///
    /// # Returns
    /// * `Ok(StagingSet)` - Staging nodes keyed by their prior hash in the trie.
    /// * `Err(StateMerkleError)` - If an error occurs during node processing or encoding.
    ///
    /// # Notes
    /// - The `HashMap` allows efficient lookup of updated child hashes for branch nodes in each iteration.
    /// - For leaf additions, two new nodes are created: a leaf and a branch.
    /// - For leaf removals, only the parent node is updated to point to the sibling.
    pub fn generate_staging_set(&self) -> Result<StagingSet, StateMerkleError> {
        let mut staging_set = StagingSet::default();

        if self.is_empty() {
            return Ok(staging_set);
        }

        for (_depth, affected_nodes) in self.iter().rev() {
            for affected_node in affected_nodes {
                match affected_node {
                    AffectedNode::Branch(branch) => {
                        let prior_hash = branch.hash;

                        // Lookup `staging_set` to check which side of its child hash was affected in the 1-level deeper depth.
                        // If the child hash was not affected, use its original hash.
                        // For some branch nodes, both the left and right child might be affected.
                        let left_hash = staging_set
                            .get(&branch.left)
                            .map_or(branch.left, |staging_left_child| staging_left_child.hash);
                        let right_hash = staging_set
                            .get(&branch.right)
                            .map_or(branch.right, |staging_right_child| staging_right_child.hash);

                        // the branch node data after state transition
                        let node_data = NodeCodec::encode_branch(&left_hash, &right_hash)?;

                        let staging_node = StagingMerkleNode {
                            hash: hash::<Blake2b256>(&node_data)?,
                            node_data,
                        };

                        staging_set.insert(prior_hash, staging_node);
                    }
                    AffectedNode::Leaf(leaf) => {
                        match &leaf.leaf_write_op_context {
                            LeafWriteOpContext::Update(ctx) => {
                                // the leaf node data after the state transition
                                let node_data = NodeCodec::encode_leaf(
                                    &ctx.leaf_state_key,
                                    &ctx.leaf_state_value,
                                )?;
                                let staging_node = StagingMerkleNode {
                                    hash: hash::<Blake2b256>(&node_data)?,
                                    node_data,
                                };

                                staging_set.insert(ctx.leaf_prior_hash, staging_node);
                            }
                            LeafWriteOpContext::Add(ctx) => {
                                // by adding a new state entry, two new entries will be added to the `MerkleDB`
                                // one for the new leaf node that holds the new state data and the other
                                // for the new branch node that will replace the position of the sibling leaf node of the new leaf node,
                                // pointing to the new leaf node and its sibling node as child nodes.

                                // create a new leaf node as a staging node
                                let added_leaf_node_data = NodeCodec::encode_leaf(
                                    &ctx.leaf_state_key,
                                    &ctx.leaf_state_value,
                                )?;
                                let added_leaf_node_hash =
                                    hash::<Blake2b256>(&added_leaf_node_data)?;

                                let added_leaf_staging_node = StagingMerkleNode {
                                    hash: added_leaf_node_hash,
                                    node_data: added_leaf_node_data,
                                };

                                // Create a new branch node as a staging node. This branch has the
                                // new leaf node and its sibling candidate node as child nodes.

                                let (new_branch_left_hash, new_branch_right_hash) =
                                    match ctx.added_leaf_child_side {
                                        ChildType::Left => {
                                            (added_leaf_node_hash, ctx.sibling_candidate_hash)
                                        }
                                        ChildType::Right => {
                                            (ctx.sibling_candidate_hash, added_leaf_node_hash)
                                        }
                                    };

                                let new_branch_node_data = NodeCodec::encode_branch(
                                    &new_branch_left_hash,
                                    &new_branch_right_hash,
                                )?;

                                let new_branch_staging_node = StagingMerkleNode {
                                    hash: hash::<Blake2b256>(&new_branch_node_data)?,
                                    node_data: new_branch_node_data,
                                };

                                staging_set.insert(added_leaf_node_hash, added_leaf_staging_node); // note: `new_leaf_node_hash`, key of this entry will not be used.
                                staging_set
                                    .insert(ctx.sibling_candidate_hash, new_branch_staging_node);
                            }
                            LeafWriteOpContext::Remove(ctx) => {
                                // by removing a state entry, only the new branch node will be added to the `MerkleDB`
                                let sibling_staging_node = StagingMerkleNode {
                                    hash: ctx.sibling_hash,
                                    node_data: vec![], // not needed
                                }; // TODO: check how the sibling stage node should be handled as a staging node

                                staging_set.insert(ctx.parent_hash, sibling_staging_node);
                            }
                        }
                    }
                }
            }
        }

        Ok(staging_set)
    }
}
