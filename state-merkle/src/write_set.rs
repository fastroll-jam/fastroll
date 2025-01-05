use crate::{codec::NodeCodec, error::StateMerkleError, types::*};
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_crypto::{hash, Blake2b256};
use rocksdb::WriteBatch;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::{Deref, DerefMut},
};

pub struct MerkleWriteSet {
    pub merkle_db_write_set: MerkleDBWriteSet,
    pub state_db_write_set: StateDBWriteSet,
}

impl MerkleWriteSet {
    pub fn new(merkle_db_write_set: MerkleDBWriteSet, state_db_write_set: StateDBWriteSet) -> Self {
        Self {
            merkle_db_write_set,
            state_db_write_set,
        }
    }
}

/// Representation of merkle node write operation which will be added to `WriteBatch` of the `MerkleDB`.
pub struct MerkleNodeWrite {
    /// Blake2b-256 hash of the `node_data` field.
    /// Used as a key to a new entry to be added in the `MerkleDB`.
    hash: Hash32,
    /// Encoded node data after state transition.
    /// Data of the new entry to be added in the `MerkleDB`.
    node_data: Vec<u8>,
}

impl MerkleNodeWrite {
    pub fn new(hash: Hash32, node_data: Vec<u8>) -> Self {
        Self { hash, node_data }
    }
}

/// A collection of merkle node entries to be written into the `MerkleDB`. Also includes the
/// new merkle root that represents the posterior state of the merkle trie after commiting it.
#[derive(Default)]
pub struct MerkleDBWriteSet {
    new_root: Hash32,
    map: HashMap<Hash32, MerkleNodeWrite>,
}

impl Deref for MerkleDBWriteSet {
    type Target = HashMap<Hash32, MerkleNodeWrite>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl DerefMut for MerkleDBWriteSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

impl MerkleDBWriteSet {
    pub fn new(inner: HashMap<Hash32, MerkleNodeWrite>) -> Self {
        Self {
            new_root: HASH32_EMPTY,
            map: inner,
        }
    }

    pub fn get_new_root(&self) -> Hash32 {
        self.new_root
    }

    fn set_new_root(&mut self, new_root: Hash32) {
        self.new_root = new_root;
    }

    /// Generates `WriteBatch` from `MerkleDBWriteSet`, converting `MerkleNodeWrite`s into `MerkleDB` entries.
    pub fn generate_write_batch(&self) -> Result<WriteBatch, StateMerkleError> {
        let mut batch = WriteBatch::default();
        // `MerkleDB` entry format: (key: Hash32(value), value: encoded node value)
        self.values().for_each(|node| {
            batch.put(node.hash.as_slice(), &node.node_data);
        });

        Ok(batch)
    }
}

/// A collection of raw state data entries for regular leaf nodes in `StateDB`.
/// Each entry is identified by a `Hash32` and contains the associated octets generated from
/// `Add` or `Update` operations.
#[derive(Default)]
pub struct StateDBWriteSet {
    inner: HashMap<Hash32, Vec<u8>>,
}

impl Deref for StateDBWriteSet {
    type Target = HashMap<Hash32, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StateDBWriteSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl StateDBWriteSet {
    pub fn new(inner: HashMap<Hash32, Vec<u8>>) -> Self {
        Self { inner }
    }

    /// Generates `WriteBatch` from `StateDBWriteSet`.
    pub fn generate_write_batch(&self) -> Result<WriteBatch, StateMerkleError> {
        let mut batch = WriteBatch::default();
        // `StateDB` entry format: (key: Hash32(value), value: raw state data)
        self.iter()
            .for_each(|(key, val)| batch.put(key.as_slice(), val));

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

    /// Generates `MerkleDBWriteSet` and `StateDBWriteSet` by iterating `AffectedNode`s from `AffectedNodesByDepth`.
    ///
    /// # Purpose
    /// This function is crucial for:
    /// * Transforming affected nodes into `MerkleNodeWrite`s ready for `MerkleDB` insertion.
    /// * Extracting a write set of the `StateDB` from the affected nodes.
    /// * Maintaining the integrity of the Merkle trie during updates.
    /// * Preparing the final state of nodes after all write operations are applied.
    ///
    /// # Process
    /// - Iterates through affected nodes bottom-up (from leaves to root).
    /// - For each node:
    ///   - `Branch` nodes: Updates child hashes based on previous iterations.
    ///   - `Leaf` nodes: Handles updates, additions, and removals differently.
    /// - Creates new `MerkleNodeWrite`s with updated data and hashes.
    /// - For `Add` or `Update` operations of `Regular` `Leaf` nodes, creates new write set entries
    ///   with the new state data and hashes.
    ///
    /// # Notes
    /// - The `HashMap` allows efficient lookup of updated child hashes for branch nodes in each iteration.
    /// - For leaf additions, two new nodes are created: a leaf and a branch.
    /// - For leaf removals, only the parent node is updated to point to the sibling.
    pub fn generate_merkle_write_set(&self) -> Result<MerkleWriteSet, StateMerkleError> {
        let mut merkle_db_write_set = MerkleDBWriteSet::default();
        let mut state_db_write_set = StateDBWriteSet::default();

        if self.is_empty() {
            return Ok(MerkleWriteSet::new(merkle_db_write_set, state_db_write_set));
        }

        let mut iter_rev = self.iter().rev().peekable();

        while let Some((_depth, affected_nodes)) = iter_rev.next() {
            let is_root_node = iter_rev.peek().is_none(); // final iteration will handle the root node

            for affected_node in affected_nodes {
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
        }

        Ok(MerkleWriteSet::new(merkle_db_write_set, state_db_write_set))
    }

    /// Processes an affected node entry and inserts one or more entries to the `MerkleWriteSet`.
    ///
    /// # Returns
    ///
    /// `Some(Hash32)` with the updated merkle root hash, if the affected node corresponds to
    /// the root node. Otherwise, returns `None`.
    fn process_affected_node(
        affected_node: &AffectedNode,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        state_db_write_set: &mut StateDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        let maybe_root = match affected_node {
            AffectedNode::Branch(branch) => {
                let prior_hash = branch.hash;

                // Lookup `merkle_db_write_set` to check which side of its child hash
                // was affected in the 1-level deeper depth.
                // If the child hash was not affected, use its original hash.
                // For some branch nodes, both the left and right child might be affected.
                let left_hash = merkle_db_write_set
                    .get(&branch.left)
                    .map_or(branch.left, |write_set_left_child| {
                        write_set_left_child.hash
                    });
                let right_hash = merkle_db_write_set
                    .get(&branch.right)
                    .map_or(branch.right, |write_set_right_child| {
                        write_set_right_child.hash
                    });

                // the branch node data after state transition
                let node_data = NodeCodec::encode_branch(&left_hash, &right_hash)?;
                let hash = hash::<Blake2b256>(&node_data)?;

                let merkle_write = MerkleNodeWrite { hash, node_data };

                merkle_db_write_set.insert(prior_hash, merkle_write);

                if is_root_node {
                    Some(hash)
                } else {
                    None
                }
            }
            AffectedNode::Leaf(leaf) => {
                match &leaf.leaf_write_op_context {
                    LeafWriteOpContext::Update(ctx) => {
                        // the leaf node data after the state transition
                        let state_value_slice = ctx.leaf_state_value.as_slice();
                        let node_data =
                            NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

                        // TODO: Currently state value hashing occurs twice: 1) `encode_leaf` 2) `insert_to_state_db_write_set`
                        Self::insert_to_state_db_write_set(state_value_slice, state_db_write_set)?;

                        let hash = hash::<Blake2b256>(&node_data)?;
                        let merkle_write = MerkleNodeWrite { hash, node_data };

                        merkle_db_write_set.insert(ctx.leaf_prior_hash, merkle_write);

                        if is_root_node {
                            Some(hash)
                        } else {
                            None
                        }
                    }
                    LeafWriteOpContext::Add(ctx) => {
                        // TODO: Handle the case where the leaf node is the only entry (and therefore becomes the root node)

                        // by adding a new state entry, two new entries will be added to the `MerkleDB`
                        // one for the new leaf node that holds the new state data and the other
                        // for the new branch node that will replace the position of the sibling leaf node of the new leaf node,
                        // pointing to the new leaf node and its sibling node as child nodes.

                        // create a new leaf node as a merkle write
                        let state_value_slice = ctx.leaf_state_value.as_slice();
                        let added_leaf_node_data =
                            NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

                        Self::insert_to_state_db_write_set(state_value_slice, state_db_write_set)?;

                        let added_leaf_node_hash = hash::<Blake2b256>(&added_leaf_node_data)?;

                        let added_leaf_write = MerkleNodeWrite {
                            hash: added_leaf_node_hash,
                            node_data: added_leaf_node_data,
                        };

                        // Create a new branch node as a merkle write. This branch has the
                        // new leaf node and its sibling candidate node as child nodes.

                        let (new_branch_left_hash, new_branch_right_hash) = match ctx
                            .added_leaf_child_side
                        {
                            ChildType::Left => (added_leaf_node_hash, ctx.sibling_candidate_hash),
                            ChildType::Right => (ctx.sibling_candidate_hash, added_leaf_node_hash),
                        };

                        let new_branch_node_data = NodeCodec::encode_branch(
                            &new_branch_left_hash,
                            &new_branch_right_hash,
                        )?;

                        let new_branch_merkle_write = MerkleNodeWrite {
                            hash: hash::<Blake2b256>(&new_branch_node_data)?,
                            node_data: new_branch_node_data,
                        };

                        merkle_db_write_set.insert(added_leaf_node_hash, added_leaf_write); // note: `new_leaf_node_hash`, key of this entry will not be used.
                        merkle_db_write_set
                            .insert(ctx.sibling_candidate_hash, new_branch_merkle_write);

                        if is_root_node {
                            Some(added_leaf_node_hash)
                        } else {
                            None
                        }
                    }
                    LeafWriteOpContext::Remove(ctx) => {
                        // by removing a state entry, only the new branch node will be added to the `MerkleDB`
                        let sibling_merkle_write = MerkleNodeWrite {
                            hash: ctx.sibling_hash,
                            node_data: vec![], // not needed
                        }; // TODO: check how the sibling merkle write should be handled

                        merkle_db_write_set.insert(ctx.parent_hash, sibling_merkle_write);

                        if is_root_node {
                            Some(ctx.parent_hash) // Note: This implies removing the root node, which were the only node in the Merkle trie.
                        } else {
                            None
                        }
                    }
                }
            }
        };

        Ok(maybe_root)
    }

    /// Inserts an entry to the `StateDBWriteSet` if the state value is larger than 32 bytes, which
    /// implies that its corresponding leaf node is a regular leaf type.
    fn insert_to_state_db_write_set(
        state_value: &[u8],
        state_db_write_set: &mut StateDBWriteSet,
    ) -> Result<(), StateMerkleError> {
        // regular leaf
        if state_value.len() > 32 {
            state_db_write_set.insert(hash::<Blake2b256>(state_value)?, state_value.to_vec());
        }
        Ok(())
    }
}
