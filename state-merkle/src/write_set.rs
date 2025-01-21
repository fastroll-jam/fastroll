use crate::{codec::NodeCodec, error::StateMerkleError, types::*, utils::bits_encode_msb};
use bit_vec::BitVec;
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_crypto::{hash, Blake2b256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Display, Formatter},
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
#[derive(Clone, Debug)]
pub struct MerkleNodeWrite {
    /// Blake2b-256 hash of the `node_data` field.
    /// Used as a key to a new entry to be added in the `MerkleDB`.
    pub hash: Hash32,
    /// Encoded node data after state transition.
    /// Data of the new entry to be added in the `MerkleDB`.
    pub node_data: Vec<u8>,
}

impl Display for MerkleNodeWrite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MerkleNodeWrite {{\n\
            \thash: {},\n\
            \tnode_data: {}\n\
            }}",
            self.hash,
            hex::encode(&self.node_data)
        )
    }
}

impl MerkleNodeWrite {
    pub fn new(hash: Hash32, node_data: Vec<u8>) -> Self {
        Self { hash, node_data }
    }
}

/// A collection of merkle node entries to be written into the `MerkleDB`. Also includes the
/// new merkle root that represents the posterior state of the merkle trie after commiting it.
///
/// The `map` is keyed by the node hash that previously existed at the position in the merkle trie
/// before the write operation represented by `MerkleNodeWrite`, so that parent nodes can look up
/// the map to get the "affected" value of their descendants.
#[derive(Debug, Default)]
pub struct MerkleDBWriteSet {
    new_root: Hash32,
    pub map: HashMap<Hash32, MerkleNodeWrite>,
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

impl Display for MerkleDBWriteSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.map.is_empty() {
            return writeln!(f, "MerkleDBWriteSet is empty");
        }

        for (key, node_write) in &self.map {
            writeln!(f, "lookup_key: {}", key)?;
            writeln!(f, "node_write: {}", node_write)?;
        }
        Ok(())
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

    pub fn entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.map
            .values()
            .map(|node_write| (&node_write.hash, &node_write.node_data))
    }
}

/// A collection of raw state data entries for regular leaf nodes in `StateDB`.
/// Each entry is identified by a `Hash32` and contains the associated octets generated from
/// `Add` or `Update` operations.
#[derive(Debug, Default)]
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

impl Display for StateDBWriteSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.inner.is_empty() {
            return writeln!(f, "StateDBWriteSet is empty");
        }

        for (state_key, state_data) in &self.inner {
            writeln!(f, "State Key: {}", state_key)?;
            writeln!(f, "Raw State Data: {}", hex::encode(state_data))?;
        }
        Ok(())
    }
}

impl StateDBWriteSet {
    pub fn new(inner: HashMap<Hash32, Vec<u8>>) -> Self {
        Self { inner }
    }

    pub fn entries(&self) -> impl Iterator<Item = (&Hash32, &Vec<u8>)> {
        self.inner.iter()
    }
}

/// FIXME: Remove `HashSet` since only one `AffectedNode` exists per depth (see `StateManager::commit_dirty_cache`)
#[derive(Debug, Default)]
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

impl Display for AffectedNodesByDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.inner.is_empty() {
            return writeln!(f, "AffectedNodesByDepth is empty");
        }

        for (depth, affected_nodes) in &self.inner {
            writeln!(f, "Depth: {}", depth)?;
            for node in affected_nodes {
                writeln!(f, "  {}", node)?;
            }
        }
        Ok(())
    }
}

impl AffectedNodesByDepth {
    pub fn new(inner: BTreeMap<usize, HashSet<AffectedNode>>) -> Self {
        Self { inner }
    }

    pub fn generate_merkle_write_set(&self) -> Result<MerkleWriteSet, StateMerkleError> {
        let mut merkle_db_write_set = MerkleDBWriteSet::default();
        let mut state_db_write_set = StateDBWriteSet::default();

        if self.is_empty() {
            return Ok(MerkleWriteSet::new(merkle_db_write_set, state_db_write_set));
        }

        let mut iter_rev = self.iter().rev().peekable();

        while let Some((_depth, affected_nodes)) = iter_rev.next() {
            // The final iteration will handle the root node (reverse iteration starting from the leaf).
            let is_root_node = iter_rev.peek().is_none();

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

    fn process_affected_node(
        affected_node: &AffectedNode,
        merkle_db_write_set: &mut MerkleDBWriteSet,
        state_db_write_set: &mut StateDBWriteSet,
        is_root_node: bool,
    ) -> Result<Option<Hash32>, StateMerkleError> {
        let maybe_root = match affected_node {
            AffectedNode::PathNode(path_node) => {
                let prior_hash = path_node.hash;

                // Lookup `merkle_db_write_set` to check which side of its child hash
                // was affected in the 1-level deeper depth.
                // If the child hash was not affected, use its original hash.
                // For some branch nodes, both the left and right child might be affected.
                let left_hash = merkle_db_write_set
                    .get(&path_node.left)
                    .map_or(path_node.left, |write_set_left_child| {
                        write_set_left_child.hash
                    });
                let right_hash = merkle_db_write_set
                    .get(&path_node.right)
                    .map_or(path_node.right, |write_set_right_child| {
                        write_set_right_child.hash
                    });

                // the branch node data after state transition
                let node_data = NodeCodec::encode_branch(&left_hash, &right_hash)?;
                let hash = hash::<Blake2b256>(&node_data)?;

                let merkle_write = MerkleNodeWrite::new(hash, node_data);

                merkle_db_write_set.insert(prior_hash, merkle_write);

                if is_root_node {
                    Some(hash)
                } else {
                    None
                }
            }
            AffectedNode::Endpoint(endpoint) => {
                match &endpoint.leaf_write_op_context {
                    LeafWriteOpContext::Add(ctx) => {
                        // `AffectedNode` is the future sibling leaf of the added leaf.

                        // FIXME: Mention decompressing path bits
                        // By adding a new state entry, two new entries will be added to the `MerkleDB`.
                        // One for the new leaf node that holds the new state data and the other
                        // for the new branch node that will replace the position of the sibling leaf node of the new leaf node,
                        // pointing to the new leaf node and its sibling node as child nodes.

                        // Create a new leaf node as a merkle write.
                        let state_value_slice = ctx.leaf_state_value.as_slice();
                        let added_leaf_node_data =
                            NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

                        Self::insert_to_state_db_write_set(state_value_slice, state_db_write_set)?;

                        let added_leaf_node_hash = hash::<Blake2b256>(&added_leaf_node_data)?;
                        let added_leaf_write =
                            MerkleNodeWrite::new(added_leaf_node_hash, added_leaf_node_data);

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
                                Some(top_level_merkle_write.hash)
                            } else {
                                None
                            }
                        } else {
                            // Case 2: affected node endpoint is single-child branch
                            merkle_db_write_set.insert(added_leaf_node_hash, added_leaf_write); // note: `new_leaf_node_hash`, key of this entry will not be used as a lookup key.
                            merkle_db_write_set.insert(endpoint.hash, new_branch_merkle_write);

                            return if is_root_node {
                                Ok(Some(new_branch_node_hash))
                            } else {
                                Ok(None)
                            };
                        }
                    }
                    LeafWriteOpContext::Update(ctx) => {
                        // the leaf node data after the state transition
                        let state_value_slice = ctx.leaf_state_value.as_slice();
                        let node_data =
                            NodeCodec::encode_leaf(&ctx.leaf_state_key, state_value_slice)?;

                        // TODO: Currently state value hashing occurs twice: 1) `encode_leaf` 2) `insert_to_state_db_write_set`
                        Self::insert_to_state_db_write_set(state_value_slice, state_db_write_set)?;

                        let hash = hash::<Blake2b256>(&node_data)?;
                        let merkle_write = MerkleNodeWrite::new(hash, node_data);

                        merkle_db_write_set.insert(ctx.leaf_prior_hash, merkle_write);
                        if is_root_node {
                            Some(hash)
                        } else {
                            None
                        }
                    }
                    LeafWriteOpContext::Remove(ctx) => {
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
                                ChildType::Left => left = HASH32_EMPTY,
                                ChildType::Right => right = HASH32_EMPTY,
                            }
                        }

                        let post_parent_data = NodeCodec::encode_branch(&left, &right)?;
                        let post_parent_data_new_hash = hash::<Blake2b256>(&post_parent_data)?;
                        merkle_db_write_set.insert(
                            ctx.post_parent_hash,
                            MerkleNodeWrite::new(post_parent_data_new_hash, post_parent_data),
                        );

                        if is_root_node {
                            Some(post_parent_data_new_hash)
                        } else {
                            None
                        }
                    }
                }
            }
        };

        Ok(maybe_root)
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
                (HASH32_EMPTY, child_hash)
            } else {
                (child_hash, HASH32_EMPTY)
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

/// Determines whether the new leaf node will be placed as the left or right child in the trie,
/// relative to the sibling node.
pub(crate) fn added_leaf_child_side(
    new_leaf_state_key: &Hash32,
    sibling_leaf_partial_state_key: &BitVec,
) -> Result<ChildType, StateMerkleError> {
    let new_leaf_state_key = bits_encode_msb(new_leaf_state_key.as_slice());
    for (new_leaf_bit, sibling_leaf_bit) in new_leaf_state_key
        .iter()
        .zip(sibling_leaf_partial_state_key.iter())
    {
        // The first bit that the new leaf and the sibling leaf diverges
        if new_leaf_bit != sibling_leaf_bit {
            return Ok(ChildType::from_bit(new_leaf_bit));
        }
    }

    Err(StateMerkleError::InvalidMerklePath)
}
