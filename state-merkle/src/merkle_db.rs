#[allow(unused_imports)]
use crate::{
    codec::{test_utils::print_node, NodeCodec},
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
    pub fn commit_write_batch(&self, write_batch: WriteBatch) -> Result<(), StateMerkleError> {
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
    /// * `Ok(Option<(LeafType, Vec<u8>)>)` - An optional tuple containing:
    ///    - The type of the leaf node (`Embedded` or `Regular`).
    ///    - The Vec<u8> representing the state data or its hash, depending on the leaf type.
    ///    - Returns `None` if a state entry with the given `state_key` is not found.
    /// * `Err(StateMerkleError)` - An error that occurred while retrieving the node data.
    ///
    /// # Note
    /// For `Regular` leaf nodes, additional steps are required to fetch the actual state data
    /// from the `StateDB` using the returned hash.
    pub fn retrieve(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<(LeafType, Vec<u8>)>, StateMerkleError> {
        // println!("\n----- Retrieval");
        let state_key_bv = bits_encode_msb(state_key.as_slice());

        let mut current_node = match self.get_node(&self.root)? {
            Some(node) => node,
            None => return Ok(None),
        }; // initialize with the root node

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

    pub fn collect_leaf_path(
        &self,
        state_key: &Hash32,
        write_op: MerkleWriteOp,
        affected_nodes: &mut AffectedNodesByDepth,
    ) -> Result<(), StateMerkleError> {
        // Initialize local state variables
        let state_key_bv = bits_encode_msb(state_key.as_slice());
        let mut current_node = match self.get_node(&self.root)? {
            Some(node) => node,
            None => return Ok(()),
        };

        // Accumulator for bits of the state key bitvec. Represents the partial merkle path
        // from the root to the certain node.
        let mut partial_merkle_path = BitVec::new();

        // Special handling for the `Remove` case
        let remove_ctx = self.collect_removal_context(&write_op)?;

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for (depth, b) in state_key_bv.iter().enumerate() {
            match current_node.check_node_type()? {
                NodeType::Branch(branch_type) => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;
                    let (child_hash, sibling_child_hash) =
                        if b { (&right, &left) } else { (&left, &right) };
                    let added_leaf_child_side = ChildType::from_bit(b);

                    // Reached endpoint of the traversal.
                    //
                    // If the current branch is of single-child type and if we're trying to
                    // add a new leaf node diverging from that branch, we should insert the
                    // current node as an affected node with relevant context data for the
                    // `Add` write operation.
                    if child_hash == &HASH32_EMPTY && branch_type.has_single_child() {
                        if let MerkleWriteOp::Add(state_key, state_value) = &write_op {
                            affected_nodes.entry(depth).or_default().insert(
                                AffectedNode::Endpoint(AffectedEndpoint {
                                    hash: current_node.hash,
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Add(
                                        LeafAddContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            sibling_candidate_hash: *sibling_child_hash,
                                            added_leaf_child_side,
                                            leaf_split_context: None, // No need to handle path decompression in this case.
                                        },
                                    ),
                                }),
                            );
                            return Ok(());
                        }

                        // If child_hash of chosen on the merkle path (following the bit `b`) is
                        // `HASH32_EMPTY` but the `write_op` is not `Add`, that implies a wrong `state_key`.
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
                            affected_nodes.entry(depth).or_default().insert(
                                AffectedNode::Endpoint(AffectedEndpoint {
                                    hash: current_node.hash,
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Remove(remove_ctx),
                                }),
                            );
                            return Ok(());
                        }
                    }

                    // Simply collect the branch node as affected node.
                    // Here, affected node stored at `depth = 0` is the root node.
                    affected_nodes
                        .entry(depth)
                        .or_default()
                        .insert(AffectedNode::PathNode(AffectedPathNode {
                            hash: current_node.hash,
                            depth,
                            left,
                            right,
                        }));

                    // Update local state variables for the next iteration (move forward along the merkle path).
                    current_node = match self.get_node(child_hash)? {
                        Some(node) => node,
                        None => return Ok(()), // TODO: This implies pollution
                    };
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
                        MerkleWriteOp::Add(state_key, state_value) => {
                            // Note: at this point, `current_node` isn't the leaf node to be added.
                            // It is the leaf node that shares the longest merkle path with the
                            // new leaf node to be `Add`ed.

                            // The partial state key of the sibling node of the new leaf node being added, extracted from its node data.
                            let leaf_state_key_248 =
                                current_node.extract_partial_leaf_state_key()?;

                            affected_nodes.entry(depth).or_default().insert(
                                AffectedNode::Endpoint(AffectedEndpoint {
                                    hash: current_node.hash,
                                    depth,
                                    leaf_write_op_context: LeafWriteOpContext::Add(
                                        LeafAddContext {
                                            leaf_state_key: *state_key,
                                            leaf_state_value: state_value.clone(),
                                            sibling_candidate_hash: current_node.hash,
                                            added_leaf_child_side: added_leaf_child_side(
                                                state_key,
                                                &leaf_state_key_248,
                                            )?,
                                            leaf_split_context: Some(LeafSplitContext {
                                                partial_merkle_path,
                                                sibling_state_key_248: leaf_state_key_248,
                                            }),
                                        },
                                    ),
                                }),
                            );
                            Ok(())
                        }
                        MerkleWriteOp::Update(state_key, state_value) => {
                            affected_nodes.entry(depth).or_default().insert(
                                AffectedNode::Endpoint(AffectedEndpoint {
                                    hash: current_node.hash,
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

    fn collect_removal_context(
        &self,
        write_op: &MerkleWriteOp,
    ) -> Result<Option<LeafRemoveContext>, StateMerkleError> {
        match write_op {
            MerkleWriteOp::Remove(state_key) => {
                // Remove operation inserts one `AffectedBranch`.
                let state_key_bv = bits_encode_msb(state_key.as_slice());
                let ctx = self.collect_removal_context_internal(&state_key_bv)?;
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
    ///   1. The hash of a full-branch ("posterior parent") that will point to the sibling
    ///      after the target leaf is removed.
    ///   2. The sibling node's hash and its position (`Left` or `Right`) relative to the
    ///      "posterior parent".
    ///
    /// - If the sibling is a `Branch`, there is no need to collect any context information.
    ///
    /// This information is used to correctly update the "posterior parent" once the removal
    /// of the target leaf is finalized.
    fn collect_removal_context_internal(
        &self,
        state_key_bv: &BitVec,
    ) -> Result<LeafRemoveContext, StateMerkleError> {
        let mut current_node = self.get_node(&self.root)?.expect("root node must exist");
        let (root_left, root_right) = NodeCodec::decode_branch(&current_node, self)?;

        // Keeping this history is needed because we shouldn't count the parent of the leaf node to be removed.
        let mut branch_history = FullBranchHistory::new(
            self.root,
            state_key_bv.get(0).expect("should not be None"),
            root_left,
            root_right,
        );

        for b in state_key_bv.iter() {
            match current_node.check_node_type()? {
                NodeType::Branch(branch_type) => {
                    let (left, right) = NodeCodec::decode_branch(&current_node, self)?;

                    if let BranchType::Full = branch_type {
                        branch_history.update(current_node.hash, b, left, right);
                    }

                    let child_hash = if b { &right } else { &left };
                    current_node = self
                        .get_node(child_hash)?
                        .ok_or(StateMerkleError::NodeNotFound)?;
                }
                NodeType::Leaf(_) => {
                    let parent_node = self
                        .get_node(&branch_history.curr.hash)?
                        .expect("parent node must exist");

                    let (left, right) = NodeCodec::decode_branch(&parent_node, self)?;

                    let sibling_hash = if b { &left } else { &right };
                    let sibling_node = self
                        .get_node(sibling_hash)?
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
                            sibling_leaf_hash: Some(*sibling_hash),
                            removal_side: branch_history.prev.navigate_to,
                        }),
                    };
                }
            }
        }

        Err(StateMerkleError::NodeNotFound)
    }
}
