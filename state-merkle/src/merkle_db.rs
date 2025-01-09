use crate::{
    codec::NodeCodec,
    error::StateMerkleError,
    types::*,
    utils::{bits_encode_msb, bitvec_to_hash32},
    write_set::{added_leaf_child_side, AffectedNodesByDepth},
};
use bit_vec::BitVec;
use dashmap::DashMap;
use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_crypto::{hash, Blake2b256};
use rjam_db::RocksDBConfig;
use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use std::sync::Arc;

/// Database and cache for storing and managing Merkle trie nodes.
pub struct MerkleDB {
    /// RocksDB instance.
    db: Arc<DB>,
    /// Cache for storing Merkle trie nodes.
    cache: Arc<DashMap<Hash32, MerkleNode>>,
    /// Root hash of the Merkle trie.
    root: Hash32,
}

impl MerkleDB {
    pub fn open(config: &RocksDBConfig, cache_size: usize) -> Result<Self, StateMerkleError> {
        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        let db = DB::open(&opts, &config.path).map_err(StateMerkleError::RocksDBError)?;

        Ok(Self {
            db: Arc::new(db),
            cache: Arc::new(DashMap::with_capacity(cache_size)),
            root: HASH32_EMPTY,
        })
    }

    pub fn root(&self) -> Hash32 {
        self.root
    }

    pub fn update_root(&mut self, new_root: Hash32) {
        self.root = new_root;
    }

    /// Restore correct hash value from a 255-bit bitvec representation, by attempting to
    /// retrieve a node from the `MerkleDB`.
    pub(crate) fn restore_hash_bit(&self, hash_bv: &BitVec) -> Result<Hash32, StateMerkleError> {
        if hash_bv.len() != 255 {
            return Err(StateMerkleError::InvalidBitVecLength(hash_bv.len()));
        }

        let mut full_bits = hash_bv.clone();

        // Try 0 bit
        full_bits.insert(0, false);
        if let Some(node_with_hash_0) = self.get_node(&bitvec_to_hash32(&full_bits)?)? {
            return Ok(node_with_hash_0.hash);
        }

        // Try 1 bit
        full_bits.set(0, true);
        if let Some(node_with_hash_1) = self.get_node(&bitvec_to_hash32(&full_bits)?)? {
            return Ok(node_with_hash_1.hash);
        }

        Err(StateMerkleError::InvalidHash32Input)
    }

    /// Get a node entry from the MerkleDB.
    pub(crate) fn get_node(
        &self,
        node_hash: &Hash32,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        // lookup the cache
        if let Some(node) = self.cache.get(node_hash) {
            return Ok(Some(node.clone()));
        }

        // fetch node data octets from the db and put into the cache
        match self.db.get(node_hash.as_slice()) {
            Ok(Some(data)) => {
                let node = MerkleNode {
                    hash: *node_hash,
                    data,
                };
                self.cache.insert(*node_hash, node.clone());
                Ok(Some(node))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn put_node(&self, node: &MerkleNode) -> Result<(), StateMerkleError> {
        self.db
            .put(node.hash.as_slice(), &node.data)
            .map_err(|e| e.into())
    }

    /// Commit a write batch for node entries into the MerkleDB.
    pub fn commit_nodes_write_batch(
        &self,
        write_batch: WriteBatch,
    ) -> Result<(), StateMerkleError> {
        let write_options = WriteOptions::default();
        self.db.write_opt(write_batch, &write_options)?;
        Ok(())
    }

    /// Retrieves the data of a leaf node at a given Merkle path, representing the state data.
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
    /// * `state_key`: [`&Hash32`] - A state key representing merkle path. The key work as merkle path to the leaf node that contains the state data.
    ///
    /// # Returns
    /// * `Ok((LeafType, Vec<u8>))` - A tuple containing:
    ///    - The type of the leaf node (`Embedded` or `Regular`).
    ///    - The Vec<u8> representing the state data or its hash, depending on the leaf type.
    /// * `Err(StateMerkleError)` - An error that occurred while retrieving the node data.
    ///
    /// # Note
    /// For `Regular` leaf nodes, additional steps may be required to fetch the actual state data
    /// from the `StateDB` using the returned hash.
    pub fn retrieve(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<(LeafType, Vec<u8>)>, StateMerkleError> {
        let state_key_bv = bits_encode_msb(state_key.as_slice());

        let mut current_node = match self.get_node(&self.root)? {
            Some(node) => node,
            None => return Ok(None),
        }; // initialize with the root node
           // print_node(&Some(current_node.clone()), self); // print the root node

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for b in &state_key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch(_) => {
                    // update the current node and proceed to the next node
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;
                    let child_hash = if b { right } else { left };
                    // print_node(&Some(current_node.clone()), self);
                    current_node = match self.get_node(&child_hash)? {
                        Some(node) => node,
                        None => return Ok(None),
                    };
                }
                NodeType::Leaf(leaf_type) => {
                    // extract the leaf value from the current node and return
                    let value = NodeCodec::get_leaf_value(&state_key_bv, &current_node)?;
                    // print_node(&Some(current_node.clone()), self);
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
    #[allow(clippy::type_complexity)]
    pub fn commit_to_empty_trie(
        &self,
        write_op: &MerkleWriteOp,
    ) -> Result<(Hash32, Option<(Hash32, Vec<u8>)>), StateMerkleError> {
        if self.root != HASH32_EMPTY {
            return Err(StateMerkleError::NotEmptyTrie);
        }

        match write_op {
            MerkleWriteOp::Add(k, v) => {
                // Add a single leaf node as the root
                let node_data = NodeCodec::encode_leaf(k, v)?;
                let node_hash = hash::<Blake2b256>(&node_data)?;
                let new_leaf = MerkleNode::new(node_hash, node_data);

                let maybe_state_db_write =
                    if let NodeType::Leaf(LeafType::Regular) = new_leaf.check_node_type()? {
                        Some((hash::<Blake2b256>(v)?, v.clone()))
                    } else {
                        None
                    };

                self.put_node(&new_leaf)?;
                self.cache.insert(node_hash, new_leaf); // optional

                Ok((node_hash, maybe_state_db_write))
            }
            MerkleWriteOp::Update(_, _) => Err(StateMerkleError::NodeNotFound),
            MerkleWriteOp::Remove(_) => Ok((HASH32_EMPTY, None)),
        }
    }

    /// FIXME: Add docs for the single-child branch nodes.
    /// Extracts all affected nodes on a path due to a write operation to be applied to a leaf node.
    ///
    /// This function traverses the Merkle trie from the root to the leaf node corresponding to the
    /// given `state_key`, collecting all nodes encountered along the path. These nodes are then
    /// added to the `affected_nodes_by_depth` map, organized by their depth in the trie.
    ///
    /// # Purpose
    /// This extraction is crucial for efficient updates in the staging trie, as it allows for:
    /// * Identifying only the nodes that need to be modified during a state transition.
    /// * Preparing these nodes for eventual commitment to the `MerkleDB`.
    /// * Maintaining the integrity of the Merkle trie structure during updates.
    ///
    /// # Write Operations
    /// The function behaves differently based on the type of write operation:
    ///
    /// ## Update Operation
    /// For an update, we traverse to the existing leaf node that matches the `state_key`. We collect
    /// information about this leaf node and all branch nodes along the path. The leaf node's value
    /// will be updated, and the hashes of all nodes along the path will need to be recalculated.
    ///
    /// ```text
    ///  (Before)              (After)
    ///
    ///   ┌─┴─┐                 ┌─┴─┐
    ///   │ B │                 │ B'│ (affected)
    ///   └─┬─┘                 └─┬─┘
    ///  ┌──┴──┐               ┌──┴───┐               (Updates an existing leaf node and recalculates hashes along the path)
    /// ┌┴─┐ ┌─┴┐             ┌┴─┐  ┌─┴─┐
    /// │L1│ │L2│             │L1│  │L2'│ (affected)
    /// └──┘ └──┘             └──┘  └───┘
    /// ```
    ///
    /// ## Add Operation
    /// When adding a new entry with `state_key`, this key doesn't exist in the current Merkle trie.
    /// As we traverse the trie, we'll reach a leaf node that shares the longest common prefix with
    /// our `state_key`. This existing leaf node will become the sibling of our new leaf node after
    /// the state transition.
    ///
    /// To insert the new node and maintain the trie structure:
    /// 1. We create a new branch node
    /// 2. This new branch node points to both:
    ///    a. The existing leaf node (the found sibling)
    ///    b. The new leaf node we're adding
    ///
    /// This process effectively "splits" the path, inserting our new node at the correct position
    /// in the trie. The function collects information about the new leaf node and its sibling.
    /// The actual construction of the new branch node occurs later outside of this function.
    ///
    /// ```text
    ///  (Before)              (After)
    ///
    ///   ┌─┴─┐                 ┌─┴─┐
    ///   │ B │                 │ B'│ (affected)
    ///   └─┬─┘                 └─┬─┘
    ///  ┌──┴──┐              ┌───┴───┐               (Inserts a new leaf node, creating a new branch node when necessary)
    /// ┌┴─┐ ┌─┴┐            ┌┴─┐   ┌─┴┐
    /// │L1│ │L2│      (new) │B1│   │L2│
    /// └──┘ └──┘            └─┬┘   └──┘
    ///                     ┌──┴──┐
    ///                    ┌┴─┐ ┌─┴┐
    ///                    │L1│ │L3│ (new)
    ///                    └──┘ └──┘
    /// ```
    ///
    /// ## Remove Operation
    /// When removing a leaf node, we traverse to the target leaf and collect information about it,
    /// its parent, and its sibling. After removal, the sibling node will be promoted to replace
    /// the parent branch node. We collect information about all nodes along the path, as their
    /// hashes will need to be recalculated.
    ///
    /// ```text
    ///    (Before)              (After)
    ///
    ///      ┌─┴─┐                ┌─┴─┐
    ///      │ B │                │ B'│ (affected)
    ///      └─┬─┘                └─┬─┘
    ///    ┌───┴───┐             ┌──┴──┐              (Removes a leaf node and adjusts the trie structure accordingly)
    ///   ┌┴─┐   ┌─┴┐           ┌┴─┐ ┌─┴┐
    ///   │B1│   │L3│           │L1│ │L3│
    ///   └─┬┘   └──┘           └──┘ └──┘
    ///  ┌──┴──┐
    /// ┌┴─┐ ┌─┴┐               ┌──┐ ┌──┐
    /// │L1│ │L2│               │B1│ │L2│ (B1, L2 removed)
    /// └──┘ └──┘               └──┘ └──┘
    /// ```
    ///
    /// # Arguments
    /// * `state_key`: [`&Hash32`] - The state key representing the Merkle path to the target leaf node.
    /// * `write_op`: [`MerkleWriteOp`] - The write operation to be applied to the leaf node.
    /// * `affected_nodes_by_depth`: [`&mut AffectedNodesByDepth`] - A mutable reference
    ///   to a collection that will store all `AffectedNode`s encountered, sorted by their depth in the trie.
    ///
    /// # Returns
    /// * `Ok(())` - The path to the leaf node was successfully traversed and affected nodes were collected.
    /// * `Err(StateMerkleError)` - An error occurred during the traversal or node collection process.
    ///
    /// # Errors
    /// This function may return an error in the following situations:
    /// * If a node is not found in the trie where expected.
    /// * If there's an issue decoding node data.
    /// * If an invalid node type is encountered.
    /// * If the state key doesn't match the expected path in the trie.
    ///
    /// # Note
    /// This function should be called iteratively for all leaf nodes affected by a state transition,
    /// typically corresponding to all state cache entries marked as `Dirty`.
    pub fn extract_path_nodes_to_leaf(
        &self,
        state_key: &Hash32,
        write_op: MerkleWriteOp,
        affected_nodes_by_depth: &mut AffectedNodesByDepth,
    ) -> Result<(), StateMerkleError> {
        // Initialize local state variables
        let state_key_bv = bits_encode_msb(state_key.as_slice());
        let mut _parent_hash = self.root;
        let mut current_node = match self.get_node(&self.root)? {
            Some(node) => node,
            None => return Ok(()),
        };

        // Accumulator for bits of the state key bitvec. Represents the partial merkle path
        // from the root to the certain node.
        let mut partial_merkle_path = BitVec::new();

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for (depth, b) in state_key_bv.iter().enumerate() {
            // Accumulate merkle path
            partial_merkle_path.push(b);

            match current_node.check_node_type()? {
                NodeType::Branch(branch_type) => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;
                    let (child_hash, sibling_child_hash, added_leaf_child_side) = if b {
                        (&right, &left, ChildType::Right)
                    } else {
                        (&left, &right, ChildType::Left)
                    };
                    if child_hash == &HASH32_EMPTY && branch_type.has_single_child() {
                        if let MerkleWriteOp::Add(state_key, state_value) = &write_op {
                            // If the current branch is of single-child type and if we're trying to
                            // add a new leaf node diverging from that branch, we should insert the
                            // current node as an affected node with relevant context data for the
                            // `Add` write operation.
                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Branch(AffectedBranch {
                                    hash: current_node.hash,
                                    depth,
                                    left,
                                    right,
                                    leaf_write_op_context: Some(LeafWriteOpContext::Add(
                                        LeafAddContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            sibling_candidate_hash: *sibling_child_hash,
                                            added_leaf_child_side,
                                            partial_merkle_path: None, // No need to handle path decompression in this case.
                                            sibling_partial_state_key: None, // No need to handle path decompression in this case.
                                        },
                                    )),
                                }),
                            );
                            return Ok(());
                        }

                        // If child_hash of chosen on the merkle path (following the bit `b`) is
                        // `HASH32_EMPTY` but the branch is not single-child type or the `write_op` is not `Add`,
                        // that case implies a wrong `state_key`.
                        return Err(StateMerkleError::NodeNotFound);
                    }

                    // Simply collect the branch node as affected node.
                    // Here, affected node stored at `depth = 0` is the root node.
                    affected_nodes_by_depth
                        .entry(depth)
                        .or_default()
                        .insert(AffectedNode::Branch(AffectedBranch {
                            hash: current_node.hash,
                            depth,
                            left,
                            right,
                            leaf_write_op_context: None,
                        }));

                    // Update local state variables for the next iteration (move forward along the merkle path).
                    current_node = match self.get_node(child_hash)? {
                        Some(node) => node,
                        None => return Ok(()), // TODO: This implies pollution
                    };
                    _parent_hash = current_node.hash;
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
                        MerkleWriteOp::Update(state_key, state_value) => {
                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Leaf(AffectedLeaf {
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Update(
                                        LeafUpdateContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            leaf_prior_hash: current_node.hash, // node hash before the `Update`
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                        MerkleWriteOp::Add(state_key, state_value) => {
                            // Note: at this point, `current_node` isn't the leaf node to be added.
                            // It is the leaf node that shares the longest merkle path with the
                            // new leaf node to be `Add`ed.

                            // The partial state key of the sibling node of the new leaf node being added, extracted from its node data.
                            let partial_leaf_state_key =
                                current_node.extract_partial_leaf_state_key()?;

                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Leaf(AffectedLeaf {
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Add(
                                        LeafAddContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            sibling_candidate_hash: current_node.hash,
                                            added_leaf_child_side: added_leaf_child_side(
                                                state_key,
                                                &partial_leaf_state_key,
                                            )?,
                                            partial_merkle_path: Some(partial_merkle_path),
                                            sibling_partial_state_key: Some(partial_leaf_state_key),
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                        MerkleWriteOp::Remove(_state_key) => {
                            unimplemented!()
                        }
                    };
                }
            }
        }

        Err(StateMerkleError::NodeNotFound)
    }
}
