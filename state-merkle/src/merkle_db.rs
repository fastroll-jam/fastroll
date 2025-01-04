use crate::{
    codec::NodeCodec,
    error::StateMerkleError,
    staging::AffectedNodesByDepth,
    types::*,
    utils::{bits_encode_msb, bitvec_to_hash32, slice_bitvec},
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

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for b in &state_key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch => {
                    // update the current node and proceed to the next node
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;
                    let child_hash = if b { right } else { left };

                    current_node = match self.get_node(&child_hash)? {
                        Some(node) => node,
                        None => return Ok(None),
                    };
                }
                NodeType::Leaf(leaf_type) => {
                    // extract the leaf value from the current node and return
                    let value = NodeCodec::get_leaf_value(&state_key_bv, &current_node)?;
                    return Ok(Some((leaf_type, value)));
                }
                NodeType::Empty => return Err(StateMerkleError::EmptyState),
            }
        }

        Ok(None)
    }

    /// Commits a single leaf-level Merkle write operations (`Add`, `Update`, or `Remove`) to the
    /// Merkle trie.
    ///
    /// Used for genesis or tests.
    pub fn commit_single(&self, write_op: &MerkleWriteOp) -> Result<(), StateMerkleError> {
        // Case 1: Trie is empty
        if self.root == HASH32_EMPTY {
            return match &write_op {
                MerkleWriteOp::Add(k, v) => {
                    // Add a single leaf node as the root
                    let node_data = NodeCodec::encode_leaf(k, v)?;
                    let node_hash = hash::<Blake2b256>(&node_data)?;
                    let new_leaf = MerkleNode::new(node_hash, node_data);

                    self.put_node(&new_leaf)?;
                    self.cache.insert(node_hash, new_leaf); // optional
                                                            // self.root = node_hash; // FIXME: requires `&mut`
                    Ok(())
                }
                MerkleWriteOp::Update(_, _) => Err(StateMerkleError::NodeNotFound),
                MerkleWriteOp::Remove(_) => Ok(()),
            };
        }

        // Case 2: Trie is not empty
        let state_key = match &write_op {
            MerkleWriteOp::Add(k, _) => k,
            MerkleWriteOp::Update(k, _) => k,
            MerkleWriteOp::Remove(k) => k,
        };

        let mut affected_nodes_by_depth = AffectedNodesByDepth::default();
        self.extract_path_nodes_to_leaf(state_key, write_op.clone(), &mut affected_nodes_by_depth)?;
        self.commit_nodes_write_batch(
            affected_nodes_by_depth
                .generate_staging_set()?
                .generate_write_batch()?,
        )?;

        Ok(())
    }

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
        let state_key_bv = bits_encode_msb(state_key.as_slice());
        let mut parent_hash = self.root;
        let mut current_node = match self.get_node(&self.root)? {
            Some(node) => node,
            None => return Ok(()),
        }; // initialize with the root node

        let mut current_child_side = None; // ChildType (Left or Right) of the current node

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for (depth, b) in state_key_bv.iter().enumerate() {
            match current_node.check_node_type()? {
                NodeType::Branch => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;

                    // Here, affected node stored at `depth = 0` is the root node
                    affected_nodes_by_depth
                        .entry(depth)
                        .or_default()
                        .insert(AffectedNode::Branch(AffectedBranch {
                            hash: current_node.hash,
                            depth,
                            left,
                            right,
                        }));

                    // move forward along the merkle path
                    let (child_hash, child_type) = if b {
                        (&right, ChildType::Right)
                    } else {
                        (&left, ChildType::Left)
                    };

                    // mutate state variables for the next iteration
                    current_node = match self.get_node(child_hash)? {
                        Some(node) => node,
                        None => return Ok(()), // TODO: This implies pollution
                    }; // update to the child node on the path
                    parent_hash = current_node.hash;
                    current_child_side = Some(child_type); // update the current child side
                }
                NodeType::Leaf(_) => {
                    match write_op {
                        MerkleWriteOp::Update(_, _) | MerkleWriteOp::Remove(_) => {
                            // If `write_op` is `Update` or `Remove`, check the state key encoded in the node
                            // data matches to `state_key` argument value.
                            let node_data_bv = bits_encode_msb(&current_node.data);
                            NodeCodec::compare_state_keys(&node_data_bv, &state_key_bv)?;

                            let key_without_last_byte =
                                slice_bitvec(&bits_encode_msb(&current_node.data), 8..256)?;
                            let state_key_without_last_byte = slice_bitvec(&state_key_bv, 0..248)?;
                            if key_without_last_byte != state_key_without_last_byte {
                                // reached to another leaf node with the same prefix
                                return Err(StateMerkleError::NodeNotFound);
                            }
                        }
                        _ => {}
                    }

                    return match &write_op {
                        MerkleWriteOp::Update(state_key, state_value) => {
                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Leaf(AffectedLeaf {
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Update(
                                        LeafUpdateContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            leaf_prior_hash: current_node.hash,
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                        MerkleWriteOp::Add(state_key, state_value) => {
                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Leaf(AffectedLeaf {
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Add(
                                        LeafAddContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            sibling_candidate_hash: current_node.hash, // note: `current_node` isn't the leaf node to be added
                                            added_leaf_child_side: current_child_side.unwrap(),
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                        MerkleWriteOp::Remove(_state_key) => {
                            // extract the sibling hash from the parent node data
                            let parent_node = match self.get_node(&parent_hash)? {
                                Some(node) => node,
                                None => return Ok(()),
                            };

                            let sibling_child_side = current_child_side.unwrap().opposite();

                            let (left, right) = NodeCodec::decode_branch(&parent_node, self)?;
                            let sibling_hash = match sibling_child_side {
                                ChildType::Left => left,
                                ChildType::Right => right,
                            };

                            affected_nodes_by_depth.entry(depth).or_default().insert(
                                AffectedNode::Leaf(AffectedLeaf {
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Remove(
                                        LeafRemoveContext {
                                            parent_hash,
                                            sibling_hash,
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                    };
                }
                NodeType::Empty => return Err(StateMerkleError::EmptyState),
            }
        }

        Err(StateMerkleError::NodeNotFound)
    }
}
