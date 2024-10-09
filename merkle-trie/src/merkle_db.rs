use crate::{
    codec::MerkleNodeCodec as NodeCodec,
    error::MerkleError,
    types::*,
    utils::{bitvec_to_hash32, bytes_to_lsb_bits, slice_bitvec},
};
use bit_vec::BitVec;
use dashmap::DashMap;
use rjam_common::{Hash32, Octets, HASH32_EMPTY};
use rocksdb::{WriteBatch, WriteOptions, DB};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

/// Merkle trie node representation.
#[derive(Clone, Debug)]
pub struct Node {
    /// Identity of the node, which is Blake2b-256 hash of the `data` field. Used as key to node entry of the MerkleDB.
    hash: Hash32,
    /// 512-bit encoded node data.
    ///
    /// The node type is encoded in the first two bits of the `data` field.
    ///
    /// Full node structures:
    /// - Branch node:        [0]  + [255-bit left child hash (partial)] + [256-bit right child hash]
    /// - Embedded leaf node: [10] + [6-bit value length] + [248-bit state key (partial)] + [encoded state value] + [zero padding]
    /// - Regular leaf node:  [11] + [248-bit state key (partial)] + [256-bit hash of encoded state value]
    data: Octets,
}

impl Node {
    /// Determines the type of the node based on its binary representation.
    fn check_node_type(&self) -> Result<NodeType, MerkleError> {
        match (
            NodeCodec::first_bit(&self.data),
            NodeCodec::second_bit(&self.data),
        ) {
            (Some(false), _) => Ok(NodeType::Branch),
            (Some(true), Some(false)) => Ok(NodeType::Leaf(LeafType::Embedded)),
            (Some(true), Some(true)) => Ok(NodeType::Leaf(LeafType::Regular)),
            _ => Err(MerkleError::InvalidNodeType),
        }
    }
}

/// Database and cache for storing and managing Merkle trie nodes.
pub struct MerkleDB {
    /// RocksDB instance.
    db: Arc<DB>,
    /// Cache for storing Merkle trie nodes.
    cache: Arc<DashMap<Hash32, Node>>,
    /// Root hash of the Merkle trie.
    root: Hash32,
}

impl MerkleDB {
    pub fn new(db: Arc<DB>, cache_size: usize) -> Result<Self, MerkleError> {
        Ok(Self {
            db,
            cache: Arc::new(DashMap::with_capacity(cache_size)),
            root: HASH32_EMPTY,
        })
    }

    /// Get a node entry from the MerkleDB from a BitVec representing a Hash32 value.
    /// For 511-bit input, try both 0 and 1 as the first bit.
    fn get_node_from_hash_bits(&self, bits: &BitVec) -> Result<Option<Node>, MerkleError> {
        match bits.len() {
            512 => {
                // for 512-bit input, construct Hash32 type and get the node
                let hash = bitvec_to_hash32(bits)?;
                self.get_node(&hash)
            }
            511 => {
                // for 511-bit input, try both 0 and 1 as the first bit
                let mut full_bits = bits.clone();
                full_bits.insert(0, false); // try 0 bit

                let hash_0 = bitvec_to_hash32(&full_bits)?;

                match self.get_node(&hash_0) {
                    Ok(node) => Ok(node),
                    Err(_) => {
                        full_bits.set(0, true);
                        let hash_1 = bitvec_to_hash32(&full_bits)?;
                        self.get_node(&hash_1)
                    }
                }
            }
            _ => Err(MerkleError::InvalidHash32Input),
        }
    }

    /// Get a node entry from the MerkleDB.
    fn get_node(&self, hash: &Hash32) -> Result<Option<Node>, MerkleError> {
        // lookup the cache
        if let Some(node) = self.cache.get(hash) {
            return Ok(Some(node.clone()));
        }

        // fetch node data octets from the db and put into the cache
        match self.db.get(hash) {
            Ok(Some(data)) => {
                let node = Node { hash: *hash, data };
                self.cache.insert(*hash, node.clone());
                Ok(Some(node))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Commit a write batch for node entries into the MerkleDB.
    pub fn commit_nodes_write_batch(&mut self, write_batch: WriteBatch) -> Result<(), MerkleError> {
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
    /// * `state_key`: [`Hash32`] - A state key representing merkle path. The key work as merkle path to the leaf node that contains the state data.
    ///
    /// # Returns
    /// * `Ok((LeafType, Octets))` - A tuple containing:
    ///    - The type of the leaf node (`Embedded` or `Regular`).
    ///    - The Octets representing the state data or its hash, depending on the leaf type.
    /// * `Err(MerkleError)` - An error that occurred while retrieving the node data.
    ///
    /// # Note
    /// For `Regular` leaf nodes, additional steps may be required to fetch the actual state data
    /// from the `StateDB` using the returned hash.
    pub fn retrieve(&self, state_key: &[u8]) -> Result<Option<(LeafType, Octets)>, MerkleError> {
        let state_key_bv = bytes_to_lsb_bits(state_key);
        let root_hash = self.root;

        let mut current_node = match self.get_node(&root_hash)? {
            Some(node) => node,
            None => return Ok(None),
        }; // initialize with the root node

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for b in &state_key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch => {
                    // update the current node and proceed to the next node
                    let child_type = if b { ChildType::Right } else { ChildType::Left };
                    let child_hash =
                        NodeCodec::get_child_hash_bits(&current_node.data, &child_type)?;
                    current_node = match self.get_node_from_hash_bits(&child_hash)? {
                        Some(node) => node,
                        None => return Ok(None),
                    }
                }
                NodeType::Leaf(leaf_type) => {
                    // extract the leaf value from the current node and return
                    let value =
                        NodeCodec::get_leaf_value(&state_key_bv, &current_node.data, &leaf_type)?;
                    return Ok(Some((leaf_type, value)));
                }
                NodeType::Empty => return Err(MerkleError::EmptyState),
            }
        }

        Ok(None)
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
    /// * `state_key`: [`Hash32`] - The state key representing the Merkle path to the target leaf node.
    /// * `write_op`: [`WriteOp`] - The write operation to be applied to the leaf node.
    /// * `affected_nodes_by_depth`: [`&mut BTreeMap<u8, HashSet<AffectedNode>>`] - A mutable reference
    ///   to a collection that will store all `AffectedNode`s encountered, sorted by their depth in the trie.
    ///
    /// # Returns
    /// * `Ok(())` - The path to the leaf node was successfully traversed and affected nodes were collected.
    /// * `Err(MerkleError)` - An error occurred during the traversal or node collection process.
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
    /// typically corresponding to all `StateCache` entries marked as `Dirty`.
    pub fn extract_path_nodes_to_leaf(
        &self,
        state_key: &[u8],
        write_op: WriteOp,
        affected_nodes_by_depth: &mut BTreeMap<u8, HashSet<AffectedNode>>, // u8 for depth of the node in the trie
    ) -> Result<(), MerkleError> {
        let state_key_bv = bytes_to_lsb_bits(state_key);
        let root_hash = self.root;
        let mut parent_hash = self.root;
        let mut current_node = match self.get_node(&root_hash)? {
            Some(node) => node,
            None => return Ok(()),
        }; // initialize with the root node
        let mut depth = 0u8;
        let mut current_child_side = None; // ChildType (Left or Right) of the current node

        // `b` determines the next sub-trie to traverse (0 for left and 1 for right)
        for b in &state_key_bv {
            match current_node.check_node_type()? {
                NodeType::Branch => {
                    let left_hash =
                        NodeCodec::get_child_hash_bits(&current_node.data, &ChildType::Left)?;
                    let right_hash =
                        NodeCodec::get_child_hash_bits(&current_node.data, &ChildType::Right)?;

                    let affected_node = AffectedNode::Branch(AffectedBranch {
                        hash: current_node.hash,
                        depth,
                        left: bitvec_to_hash32(&left_hash)?,
                        right: bitvec_to_hash32(&right_hash)?,
                    });

                    let (child_hash, child_type) = if b {
                        (&right_hash, ChildType::Right)
                    } else {
                        (&left_hash, ChildType::Left)
                    };
                    current_child_side = Some(child_type); // update the current child side

                    parent_hash = current_node.hash;

                    current_node = match self.get_node_from_hash_bits(child_hash)? {
                        Some(node) => node,
                        None => return Ok(()),
                    };
                    // update to the child node on the path

                    affected_nodes_by_depth
                        .entry(depth)
                        .or_insert_with(HashSet::new)
                        .insert(affected_node);
                }
                NodeType::Leaf(_leaf_type) => {
                    match write_op {
                        WriteOp::Update(_, _) | WriteOp::Remove(_) => {
                            // If `write_op` is `Update` or `Remove`, check the state key encoded in the node
                            // data matches to `state_key` argument value.
                            let node_data_bv = bytes_to_lsb_bits(&current_node.data);
                            NodeCodec::compare_state_keys(&node_data_bv, &state_key_bv)?;

                            let key_without_last_byte =
                                slice_bitvec(&bytes_to_lsb_bits(&current_node.data), 8..256)?;
                            let state_key_without_last_byte = slice_bitvec(&state_key_bv, 0..248)?;
                            if key_without_last_byte != state_key_without_last_byte {
                                // reached to another leaf node with the same prefix
                                return Err(MerkleError::NodeNotFound);
                            }
                        }
                        _ => {}
                    }

                    return match &write_op {
                        WriteOp::Update(state_key, state_value) => {
                            let affected_node = AffectedNode::Leaf(AffectedLeaf {
                                depth,
                                leaf_write_op_context: LeafWriteOpContext::Update(
                                    LeafUpdateContext {
                                        leaf_state_key: state_key.clone(),
                                        leaf_state_value: state_value.clone(),
                                        leaf_prior_hash: current_node.hash,
                                    },
                                ),
                            });
                            affected_nodes_by_depth
                                .entry(depth)
                                .or_insert_with(HashSet::new)
                                .insert(affected_node);
                            Ok(())
                        }
                        WriteOp::Add(state_key, state_value) => {
                            let affected_node = AffectedNode::Leaf(AffectedLeaf {
                                depth,
                                leaf_write_op_context: LeafWriteOpContext::Add(LeafAddContext {
                                    leaf_state_key: state_key.clone(),
                                    leaf_state_value: state_value.clone(),
                                    sibling_candidate_hash: current_node.hash, // note: `current_node` isn't the leaf node to be added
                                    added_leaf_child_side: current_child_side.unwrap(),
                                }),
                            });

                            affected_nodes_by_depth
                                .entry(depth)
                                .or_insert_with(HashSet::new)
                                .insert(affected_node);
                            Ok(())
                        }
                        WriteOp::Remove(_state_key) => {
                            // extract the sibling hash from the parent node data
                            let parent_node_data = match self.get_node(&parent_hash)? {
                                Some(node) => node.data,
                                None => return Ok(()),
                            };

                            let sibling_child_side = current_child_side.unwrap().opposite();
                            let sibling_hash = match self.get_node_from_hash_bits(
                                &NodeCodec::get_child_hash_bits(
                                    &parent_node_data,
                                    &sibling_child_side,
                                )?,
                            )? {
                                Some(node) => node.hash,
                                None => return Ok(()),
                            };

                            let affected_node = AffectedNode::Leaf(AffectedLeaf {
                                depth,
                                leaf_write_op_context: LeafWriteOpContext::Remove(
                                    LeafRemoveContext {
                                        parent_hash,
                                        sibling_hash,
                                    },
                                ),
                            });

                            affected_nodes_by_depth
                                .entry(depth)
                                .or_insert_with(HashSet::new)
                                .insert(affected_node);
                            Ok(())
                        }
                    };
                }
                NodeType::Empty => return Err(MerkleError::EmptyState),
            }
            depth += 1;
        }

        return Err(MerkleError::NodeNotFound);
    }
}
