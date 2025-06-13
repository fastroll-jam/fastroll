use crate::{
    affected_nodes::{AffectedEndpoint, AffectedNode, AffectedNodesByDepth, AffectedPathNode},
    codec::NodeCodec,
    error::StateMerkleError,
    types::{
        nodes::{BranchType, ChildType, LeafType, MerkleNode, NodeType},
        write_context::{
            FullBranchHistory, LeafAddContext, LeafRemoveContext, LeafSplitContext,
            LeafUpdateContext, LeafWriteOpContext,
        },
    },
    utils::{added_leaf_child_side, bits_encode_msb, bitvec_to_hash32, log_node_data},
    write_set::DBWriteSet,
};
use bit_vec::BitVec;
use dashmap::DashMap;
use fr_common::{Hash32, StateKey};
use fr_crypto::{hash, Blake2b256};
use fr_db::{
    core::{cached_db::CachedDB, core_db::CoreDB},
    ColumnFamily, WriteBatch,
};
use std::sync::{Arc, Mutex};

/// Leaf node write operations.
#[derive(Clone, Hash, PartialEq, Eq)]
pub enum MerkleWriteOp {
    Add(StateKey, Vec<u8>),    // (state_key, state_val)
    Update(StateKey, Vec<u8>), // (state_key, state_val)
    Remove(StateKey),          // state_key
}

/// Interim state of uncommitted Merkle nodes maintained during batch commitments.
pub struct WorkingSet {
    /// Uncommitted Merkle root
    root: Mutex<Hash32>,
    nodes: DashMap<Hash32, MerkleNode>,
}

impl WorkingSet {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            root: Mutex::new(Hash32::default()),
            nodes: DashMap::new(),
        }
    }

    pub fn root(&self) -> Hash32 {
        self.root.lock().unwrap().clone()
    }

    /// Retrieves a node that might be uncommitted in the working set.
    /// If not found here, the caller can fallback to reading from RocksDB.
    pub fn get_node(&self, node_hash: &Hash32) -> Option<MerkleNode> {
        self.nodes.get(node_hash).map(|entry| entry.value().clone())
    }

    /// Inserts or updates a Merkle node in the working set, so subsequent lookups see it.
    pub fn insert_node(&self, node: MerkleNode) {
        self.nodes.insert(node.hash.clone(), node);
    }

    pub fn update_root(&self, new_root: Hash32) {
        *self.root.lock().unwrap() = new_root;
    }
}

/// The main storage to store State Merkle Trie nodes.
///
/// `db` is a cached key-value database to store the trie nodes.
/// Entries of the `db` are keyed by node hash.
pub struct MerkleDB {
    /// A handle to the `CachedDB`.
    db: CachedDB<Hash32, MerkleNode>,
    /// Root hash of the Merkle trie.
    root: Mutex<Hash32>,
    /// Working set of uncommitted Merkle nodes.
    pub working_set: WorkingSet,
    /// A cache storing the mapping of the last 255 bits of a left child's node hash to its first bit.
    /// When a branch node is encoded from two child nodes, the first bit of the left child's hash
    /// is dropped. This cache helps to reconstruct the full left child hash from branch node data,
    /// reducing DB hits.
    pub node_hash_cache: DashMap<BitVec, bool>,
}

impl MerkleDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
            root: Mutex::new(Hash32::default()),
            working_set: WorkingSet::new(),
            node_hash_cache: DashMap::new(),
        }
    }

    pub fn cf_handle(&self) -> Result<&ColumnFamily, StateMerkleError> {
        Ok(self.db.cf_handle()?)
    }

    pub fn root_with_working_set(&self) -> Hash32 {
        if self.working_set.root() != Hash32::default() {
            self.working_set.root()
        } else {
            self.root()
        }
    }

    pub fn root(&self) -> Hash32 {
        self.root.lock().unwrap().clone()
    }

    pub fn update_root(&self, new_root: Hash32) {
        *self.root.lock().unwrap() = new_root
    }

    /// Restore correct hash value from a 255-bit bitvec representation, by attempting to
    /// retrieve a node from the `MerkleDB`.
    pub(crate) async fn restore_hash_bit(
        &self,
        hash_bv: &BitVec,
    ) -> Result<Hash32, StateMerkleError> {
        if hash_bv.len() != 255 {
            return Err(StateMerkleError::InvalidBitVecLength(hash_bv.len()));
        }

        let is_empty_hash = !hash_bv.any();
        if is_empty_hash {
            return Ok(Hash32::default());
        }

        let mut full_bits = hash_bv.clone();

        // Check the node hash cache
        if let Some(first_bit) = self.node_hash_cache.get(hash_bv) {
            full_bits.insert(0, *first_bit);
            return bitvec_to_hash32(&full_bits);
        }

        // Try 0 bit
        full_bits.insert(0, false);
        if let Some(node_with_hash_0) = self
            .get_node_with_working_set(&bitvec_to_hash32(&full_bits)?)
            .await?
        {
            // Insert to the node hash cache
            self.node_hash_cache.insert(hash_bv.clone(), false);
            return Ok(node_with_hash_0.hash);
        }

        // Try 1 bit
        full_bits.set(0, true);
        if let Some(node_with_hash_1) = self
            .get_node_with_working_set(&bitvec_to_hash32(&full_bits)?)
            .await?
        {
            // Insert to the node hash cache
            self.node_hash_cache.insert(hash_bv.clone(), true);
            return Ok(node_with_hash_1.hash);
        }

        Err(StateMerkleError::InvalidHash32Input)
    }

    /// Get a node entry, first looking up the working set of the MerkleDB
    /// and then looking into the DB storage if not found from the WorkingSet.
    pub(crate) async fn get_node_with_working_set(
        &self,
        node_hash: &Hash32,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        // Check if `node_hash` is in the `WorkingSet` first
        if let Some(uncommitted_node) = self.working_set.get_node(node_hash) {
            return Ok(Some(uncommitted_node));
        }
        // If not found in the `WorkingSet`, fallback to the real DB
        self.get_node(node_hash).await
    }

    /// Get a node entry from the MerkleDB.
    pub(crate) async fn get_node(
        &self,
        node_hash: &Hash32,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        // empty node
        if node_hash == &Hash32::default() {
            return Ok(None);
        }
        Ok(self.db.get_entry(node_hash).await?)
    }

    pub(crate) async fn put_node(&self, node: MerkleNode) -> Result<(), StateMerkleError> {
        Ok(self.db.put_entry(&node.hash.clone(), node).await?)
    }

    /// Commit a write batch for node entries into the MerkleDB.
    pub async fn commit_write_batch(&self, batch: WriteBatch) -> Result<(), StateMerkleError> {
        Ok(self.db.commit_write_batch(batch).await?)
    }

    pub fn clear_working_set(&self) {
        self.working_set.nodes.clear();
    }

    /// Retrieves the data of a leaf node at a given Merkle path, representing the encoded state data.
    ///
    /// This function traverses the Merkle trie using the provided `state_key` as the path,
    /// and returns the data stored in the corresponding leaf node.
    ///
    /// # Leaf Node Types
    /// The function handles retrieving two types of leaf nodes:
    ///
    /// ## Embedded Leaf Node
    /// - The state data is encoded directly as part of the leaf node itself.
    /// - Used for smaller state values that can fit within the node structure (<= 32 bytes).
    ///
    /// ## Regular Leaf Node
    /// - The leaf node contains a `Blake2b-256` hash of the state data.
    /// - This hash serves as a key for fetching the actual state data from the `StateDB`.
    /// - The state data is encoded using `JamCodec` and stored separately.
    /// - Used for larger state values (> 32 bytes), with no size limit on the encoded data in the `StateDB`.
    ///
    /// # Arguments
    /// * `state_key`: [`&StateKey`] - A state key representing merkle path. The key work as merkle path to the leaf node that contains the state data.
    ///
    /// # Returns
    /// * `Ok(Option<(LeafType, Vec<u8>)>)` - An optional tuple containing:
    ///    - The type of the leaf node (`Embedded` or `Regular`).
    ///    - The Vec<u8> representing the state data or its hash, depending on the leaf type.
    ///    - Returns `None` if a state entry with the given `state_key` is not found.
    /// * `Err(StateMerkleError)` - An error that occurred while retrieving the node data.
    ///
    /// # Note
    /// For `Regular` leaf nodes, additional steps are required to fetch the actual state data
    /// from the `StateDB` using the returned hash.
    pub async fn retrieve(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<(LeafType, Vec<u8>)>, StateMerkleError> {
        // println!("\n----- Retrieval");
        let state_key_bv = bits_encode_msb(state_key.as_slice());

        // initialize with the root node
        let Some(mut current_node) = self.get_node(&self.root()).await? else {
            return Ok(None);
        };

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for b in &state_key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch(_) => {
                    // update the current node and proceed to the next node
                    let (left, right) = NodeCodec::decode_branch(&current_node, self).await?;
                    let child_hash = if b { right } else { left };
                    log_node_data(&Some(current_node.clone()), self).await;
                    let Some(node) = self.get_node(&child_hash).await? else {
                        return Ok(None);
                    };
                    current_node = node;
                }
                NodeType::Leaf(leaf_type) => {
                    // extract the leaf value from the current node and return
                    let value = NodeCodec::get_leaf_value(&state_key_bv, &current_node)?;
                    log_node_data(&Some(current_node.clone()), self).await;
                    return Ok(Some((leaf_type, value)));
                }
            }
        }

        Ok(None)
    }

    /// Commits a single `MerkleWriteOp` into the `MerkleDB` when the merkle trie is empty.
    /// Used only for the merkle trie initialization.
    ///
    /// Returns (new_root, Option<(state_key, state_val)>)
    pub async fn commit_to_empty_trie(
        &self,
        write_op: &MerkleWriteOp,
    ) -> Result<(Hash32, Option<(Hash32, Vec<u8>)>), StateMerkleError> {
        if self.root() != Hash32::default() {
            return Err(StateMerkleError::NotEmptyTrie);
        }

        match write_op {
            MerkleWriteOp::Add(k, v) => {
                // Add a single leaf node as the root
                let node_data = NodeCodec::encode_leaf(k, v)?;
                let node_hash = hash::<Blake2b256>(&node_data)?;
                let new_leaf = MerkleNode::new(node_hash.clone(), node_data);

                let maybe_state_db_write =
                    if let NodeType::Leaf(LeafType::Regular) = new_leaf.check_node_type()? {
                        Some((hash::<Blake2b256>(v)?, v.clone()))
                    } else {
                        None
                    };

                self.put_node(new_leaf).await?;

                Ok((node_hash, maybe_state_db_write))
            }
            MerkleWriteOp::Update(_, _) => Err(StateMerkleError::NodeNotFound),
            MerkleWriteOp::Remove(_) => Ok((Hash32::default(), None)),
        }
    }

    /// Traverses the Merkle trie down to the leaf node that the `state_key` represents to
    /// collect nodes that are affected by the given merkle write operation.
    /// Then, generates `MerkleWriteSet` from the collected `AffectedNode`s.
    pub async fn collect_write_set(
        &self,
        state_key: &StateKey,
        write_op: MerkleWriteOp,
    ) -> Result<DBWriteSet, StateMerkleError> {
        // Initialize local state variables
        let mut affected_nodes = AffectedNodesByDepth::default();
        let state_key_bv = bits_encode_msb(state_key.as_slice());
        let Some(mut current_node) = self
            .get_node_with_working_set(&self.root_with_working_set())
            .await?
        else {
            return Ok(DBWriteSet::default());
        };

        // Accumulator for bits of the state key bitvec. Represents the partial merkle path
        // from the root to the current node.
        let mut partial_merkle_path = BitVec::new();

        // Special handling for the `Remove` case
        let remove_ctx = self.collect_removal_context(&write_op).await?;

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for (depth, b) in state_key_bv.iter().enumerate() {
            match current_node.check_node_type()? {
                NodeType::Branch(branch_type) => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self).await?;
                    let (child_hash, sibling_child_hash) = if b {
                        (right.clone(), left.clone())
                    } else {
                        (left.clone(), right.clone())
                    };

                    // Reached endpoint of the traversal.
                    //
                    // If the current branch is of single-child type and if we're trying to
                    // add a new leaf node diverging from that branch, we should insert the
                    // current node as an affected node with relevant context data for the
                    // `Add` write operation.
                    if child_hash == Hash32::default() && branch_type.has_single_child() {
                        if let MerkleWriteOp::Add(state_key, state_val) = write_op {
                            let endpoint = Self::create_add_branch_endpoint(
                                &current_node,
                                b,
                                state_key,
                                &state_val,
                                depth,
                                sibling_child_hash,
                            );
                            affected_nodes.insert(depth, endpoint);
                            return affected_nodes.into_merkle_write_set(self);
                        }

                        // If child_hash of chosen on the merkle path (following the bit `b`) is
                        // `Hash32::default()` but the `write_op` is not `Add`, that implies a wrong `state_key`.
                        return Err(StateMerkleError::NodeNotFound);
                    }

                    // Reached endpoint of the traversal.
                    //
                    // If the write_op is `Remove` and we've reached the deepest full-branch node
                    // to be modified, which were detected by `collect_removal_context`,
                    // insert that node as affected node and finish the iteration.
                    // `LeafRemoveContext.post_parent_hash` works as a stopper.
                    if let MerkleWriteOp::Remove(_state_key) = &write_op {
                        let remove_ctx = remove_ctx.clone().expect("should exist for removal case");
                        if current_node.hash == remove_ctx.post_parent_hash {
                            let endpoint = Self::create_remove_branch_endpoint(
                                &current_node,
                                depth,
                                remove_ctx,
                            );
                            affected_nodes.insert(depth, endpoint);
                            return affected_nodes.into_merkle_write_set(self);
                        }
                    }

                    // Simply collect the branch node as affected node.
                    // Here, affected node stored at `depth = 0` is the root node.
                    affected_nodes.insert(
                        depth,
                        AffectedNode::PathNode(AffectedPathNode {
                            hash: current_node.hash,
                            depth,
                            left,
                            right,
                        }),
                    );

                    // Update local state variables for the next iteration (move forward along the merkle path).
                    let Some(node) = self.get_node_with_working_set(&child_hash).await? else {
                        return Err(StateMerkleError::NodeNotFound);
                    };
                    current_node = node;
                }
                NodeType::Leaf(_) => {
                    // If `write_op` is `Update` or `Remove`, check the state key encoded in the node
                    // data matches to `state_key` argument value.
                    match write_op {
                        MerkleWriteOp::Update(_, _) | MerkleWriteOp::Remove(_) => {
                            let node_data_bv = bits_encode_msb(&current_node.data);
                            NodeCodec::compare_state_keys(&node_data_bv, &state_key_bv)?;
                        }
                        _ => {}
                    }

                    // Collect the leaf node with relevant context of adjacent nodes
                    // depending on the operation type.
                    return match &write_op {
                        MerkleWriteOp::Add(state_key, state_val) => {
                            // Reached endpoint of the traversal.
                            //
                            // Note: at this point, `current_node` isn't the leaf node to be added.
                            // It is the leaf node that shares the longest merkle path with the
                            // new leaf node to be `Add`ed.
                            let endpoint = Self::create_add_leaf_endpoint(
                                &current_node,
                                state_key.clone(),
                                state_val,
                                depth,
                                partial_merkle_path,
                            )?;
                            affected_nodes.insert(depth, endpoint);
                            affected_nodes.into_merkle_write_set(self)
                        }
                        MerkleWriteOp::Update(state_key, state_val) => {
                            // Reached endpoint of the traversal.
                            let endpoint = Self::create_update_leaf_endpoint(
                                &current_node,
                                state_key.clone(),
                                state_val,
                                depth,
                            );
                            affected_nodes.insert(depth, endpoint);
                            affected_nodes.into_merkle_write_set(self)
                        }
                        MerkleWriteOp::Remove(_state_key) => {
                            Err(StateMerkleError::MerkleRemovalFailed)
                        }
                    };
                }
            }

            // Accumulate merkle path
            partial_merkle_path.push(b);
        }

        Err(StateMerkleError::NodeNotFound)
    }

    fn create_add_branch_endpoint(
        current_node: &MerkleNode,
        child_side: bool,
        state_key: StateKey,
        state_val: &[u8],
        depth: usize,
        sibling_child_hash: Hash32,
    ) -> AffectedNode {
        AffectedNode::Endpoint(AffectedEndpoint {
            hash: current_node.hash.clone(),
            depth,
            leaf_write_op_context: LeafWriteOpContext::Add(LeafAddContext {
                leaf_state_key: state_key,
                leaf_state_val: state_val.to_vec(),
                sibling_candidate_hash: sibling_child_hash,
                added_leaf_child_side: ChildType::from_bit(child_side),
                leaf_split_context: None, // No need to handle path decompression in this case.
            }),
        })
    }

    fn create_remove_branch_endpoint(
        current_node: &MerkleNode,
        depth: usize,
        remove_ctx: LeafRemoveContext,
    ) -> AffectedNode {
        AffectedNode::Endpoint(AffectedEndpoint {
            hash: current_node.hash.clone(), // post parent node
            depth,
            leaf_write_op_context: LeafWriteOpContext::Remove(remove_ctx),
        })
    }

    fn create_add_leaf_endpoint(
        current_node: &MerkleNode,
        state_key: StateKey,
        state_val: &[u8],
        depth: usize,
        partial_merkle_path: BitVec,
    ) -> Result<AffectedNode, StateMerkleError> {
        // The state key of the sibling node
        // of the new leaf node being added, extracted from its node data.
        let leaf_state_key_bv = current_node.extract_leaf_state_key_bv()?;
        Ok(AffectedNode::Endpoint(AffectedEndpoint {
            hash: current_node.hash.clone(),
            depth,
            leaf_write_op_context: LeafWriteOpContext::Add(LeafAddContext {
                leaf_state_key: state_key.clone(),
                leaf_state_val: state_val.to_vec(),
                sibling_candidate_hash: current_node.hash.clone(),
                added_leaf_child_side: added_leaf_child_side(state_key, &leaf_state_key_bv)?,
                leaf_split_context: Some(LeafSplitContext {
                    partial_merkle_path,
                    sibling_state_key_bv: leaf_state_key_bv,
                }),
            }),
        }))
    }

    fn create_update_leaf_endpoint(
        current_node: &MerkleNode,
        state_key: StateKey,
        state_val: &[u8],
        depth: usize,
    ) -> AffectedNode {
        AffectedNode::Endpoint(AffectedEndpoint {
            hash: current_node.hash.clone(),
            depth,
            leaf_write_op_context: LeafWriteOpContext::Update(LeafUpdateContext {
                leaf_state_key: state_key,
                leaf_state_val: state_val.to_vec(),
                leaf_prior_hash: current_node.hash.clone(), // node hash before the `Update`
            }),
        })
    }

    async fn collect_removal_context(
        &self,
        write_op: &MerkleWriteOp,
    ) -> Result<Option<LeafRemoveContext>, StateMerkleError> {
        match write_op {
            MerkleWriteOp::Remove(state_key) => {
                // Remove operation inserts one `AffectedBranch`.
                let state_key_bv = bits_encode_msb(state_key.as_slice());
                let ctx = self.collect_removal_context_internal(&state_key_bv).await?;
                Ok(Some(ctx))
            }
            _ => Ok(None),
        }
    }

    /// Traverses the Merkle trie from the root to the target leaf that will be removed,
    /// gathering the context needed to perform the removal. Specifically, it determines:
    ///
    /// - Whether the sibling of the target leaf is a `Branch` or a `Leaf`.
    /// - If the sibling is a `Leaf`, collects:
    ///   1. The hash of a full-branch node that will be parent node of the sibling
    ///      after the target leaf is removed ("posterior parent").
    ///   2. The sibling node's hash and its position (`Left` or `Right`) relative to the
    ///      "posterior parent".
    ///
    /// - If the sibling is a `Branch`, there is no need to collect any context information.
    ///
    /// This information is used to correctly update the "posterior parent" once the removal
    /// of the target leaf is finalized.
    async fn collect_removal_context_internal(
        &self,
        state_key_bv: &BitVec,
    ) -> Result<LeafRemoveContext, StateMerkleError> {
        let mut current_node = self
            .get_node_with_working_set(&self.root())
            .await?
            .expect("root node must exist");
        let (root_left, root_right) = NodeCodec::decode_branch(&current_node, self).await?;

        // Keeping this history is needed because we shouldn't count the parent of the leaf node to be removed.
        let mut branch_history = FullBranchHistory::new(
            self.root(),
            state_key_bv.get(0).expect("should not be None"),
            root_left,
            root_right,
        );

        // Tracking the most recently seen sibling hash here.
        let mut last_sibling_hash = Hash32::default();

        for b in state_key_bv.iter() {
            match current_node.check_node_type()? {
                NodeType::Branch(branch_type) => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self).await?;

                    if let BranchType::Full = branch_type {
                        branch_history.update(current_node.hash, b, left.clone(), right.clone());
                    }

                    let (child_hash, sibling_hash) = if b { (right, left) } else { (left, right) };
                    last_sibling_hash = sibling_hash;

                    current_node = self
                        .get_node_with_working_set(&child_hash)
                        .await?
                        .ok_or(StateMerkleError::NodeNotFound)?;
                }
                NodeType::Leaf(_) => {
                    let sibling_node = self
                        .get_node_with_working_set(&last_sibling_hash)
                        .await?
                        .expect("sibling node must exist");

                    return match sibling_node.check_node_type()? {
                        NodeType::Branch(_) => Ok(LeafRemoveContext {
                            post_parent_hash: branch_history.curr.hash,
                            prior_left: branch_history.curr.left_child,
                            prior_right: branch_history.curr.right_child,
                            sibling_leaf_hash: None,
                            removal_side: branch_history.curr.navigate_to,
                        }),
                        NodeType::Leaf(_) => Ok(LeafRemoveContext {
                            post_parent_hash: branch_history.prev.hash,
                            prior_left: branch_history.prev.left_child,
                            prior_right: branch_history.prev.right_child,
                            sibling_leaf_hash: Some(last_sibling_hash),
                            removal_side: branch_history.prev.navigate_to,
                        }),
                    };
                }
            }
        }

        Err(StateMerkleError::NodeNotFound)
    }
}
