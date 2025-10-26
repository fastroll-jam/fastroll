#![allow(dead_code)]
use crate::cache::{CacheEntry, CacheEntryStatus, StateMut};
use fr_codec::prelude::*;
use fr_common::{ByteEncodable, MerkleRoot, NodeHash, StateKey, HASH_SIZE};
use fr_crypto::{hash, Blake2b256};
use fr_db::core::cached_db::DBKey;
use fr_state_merkle_v2::{
    merkle_change_set::{
        DBWriteSet, MerkleChangeSet, MerkleDBLeafPathsWrite, MerkleDBNodesWrite,
        MerkleDBWriteBatch, StateDBWrite,
    },
    merkle_db::MerkleDB,
    types::{BranchNode, LeafNode, LeafNodeData, MerkleNode, MerklePath, StateMerkleError},
    utils::{bits_decode_msb, bits_encode_msb, derive_final_leaf_paths},
};
use std::collections::HashSet;

/// A write set prepared for the later commitment to `MerkleDB` & `StateDB`
/// and the new Merkle root produced by them, which are the artifacts of dirty state cache processing.
#[derive(Clone)]
pub struct DBWriteSetWithRoot {
    pub new_merkle_root: MerkleRoot,
    pub db_write_set: DBWriteSet,
}

pub struct MerkleManager {
    merkle_db: MerkleDB,
    merkle_change_set: MerkleChangeSet,
}

impl MerkleManager {
    pub fn new(merkle_db: MerkleDB) -> Self {
        Self {
            merkle_db,
            merkle_change_set: MerkleChangeSet::default(),
        }
    }

    pub fn merkle_root(&self) -> &MerkleRoot {
        self.merkle_db.root()
    }

    /// Retrieves the data of a leaf node at a given Merkle path, representing the encoded state data.
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
    /// # Note
    /// For `Regular` leaf nodes, additional steps are required to fetch the actual state data
    /// from the `StateDB` using the returned hash.
    pub async fn retrieve(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<LeafNodeData>, StateMerkleError> {
        Ok(self
            .merkle_db
            .get_leaf(state_key)
            .await?
            .map(|leaf| leaf.data))
    }

    /// Finds the longest Merkle path that is prefix of the given state key from the
    /// `MerkleChangeSet` and the `MerkleDB`. This is used for determining the right position of
    /// a leaf node to be inserted when processing dirty cache entries with `StateMut::Add` operation.
    ///
    /// We should check whether a prefix found from the DB is marked as removed in `MerkleChangeSet`,
    /// since `StateMut::Add` operation might happen after several `StateMut::Remove` operations.
    ///
    /// Therefore, we should find the longest prefix among the following groups of merkle paths:
    /// 1. Found in the DB, not found in the ChangeSet.
    /// 2. Found in the DB, exists in the ChangeSet but not marked as removed.
    /// 3. Not found in the DB, exists in the ChangeSet but not marked as removed.
    async fn find_longest_prefix(
        &self,
        state_key: &StateKey,
    ) -> Result<MerklePath, StateMerkleError> {
        let state_key_as_merkle_path = MerklePath(bits_encode_msb(state_key.as_slice()));

        let lcp_from_db = self.merkle_db.find_longest_prefix(state_key).await?;
        // Check all ancestor paths of `lcp_from_db` as candidates
        let mut lcp_candidates: HashSet<MerklePath> =
            lcp_from_db.all_paths_to_root().into_iter().collect();

        // Find candidates from the MerkleChangeSet
        let lcp_from_change_set: HashSet<MerklePath> = self
            .merkle_change_set
            .nodes
            .keys()
            .filter(|&key_in_change_set| {
                state_key_as_merkle_path.0.starts_with(&key_in_change_set.0)
            })
            .cloned()
            .collect();

        lcp_candidates.extend(lcp_from_change_set);

        // Find the longest common prefix
        let mut lcp = MerklePath::root();
        for candidate in lcp_candidates {
            if candidate.0.len() > lcp.0.len() {
                match self.merkle_change_set.get_node(&candidate) {
                    Some(Some(_)) => {
                        // Marked as updated in ChangeSet; update the LCP.
                        lcp = candidate;
                    }
                    Some(None) => {
                        // Marked as removed in ChangeSet; not a valid candidate.
                    }
                    None => {
                        // Not found in the ChangeSet; since the candidate is ancestor of the
                        // `lcp_from_db`, it should always exist in the DB. No further check needed.
                        lcp = candidate;
                    }
                }
            }
        }

        Ok(lcp)
    }

    /// Gets a node at the given merkle path from the `MerkleChangeSet`, then falls back to
    /// `MerkleDB` search if not found.
    ///
    /// `None` return value implies either it was removed from the `MerkleChangeSet` while processing
    /// dirty state cache entries, or it never existed at the `MerkleDB`.
    async fn get_node(
        &self,
        merkle_path: &MerklePath,
    ) -> Result<Option<MerkleNode>, StateMerkleError> {
        // Get from the MerkleChangeSet
        if let Some(node_from_change_set) = self.merkle_change_set.get_node(merkle_path) {
            Ok(node_from_change_set)
        } else {
            // Fallback to MerkleDB search
            Ok(self.merkle_db.get_node(merkle_path).await?)
        }
    }

    /// Gets a leaf node merkle path that corresponds to the given state key from the `MerkleChangeSet`,
    /// then falls back to `MerkleDB` search if not found.
    ///
    /// `None` return value implies either it was removed from the `MerkleChangeSet` while processing
    /// dirty state cache entries, or it never existed at the `MerkleDB`.
    async fn get_leaf_path(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<MerklePath>, StateMerkleError> {
        // Get from the MerkleChangeSet
        if let Some(leaf_path_from_change_set) = self.merkle_change_set.get_leaf_path(state_key) {
            Ok(leaf_path_from_change_set)
        } else {
            // Fallback to MerkleDB search
            Ok(self.merkle_db.get_leaf_path(state_key).await?)
        }
    }

    /// Gets a merkle node with the longest common path with the given state key found from the MerkleDB.
    async fn get_longest_common_path_node(
        &self,
        state_key: &StateKey,
    ) -> Result<(Option<MerkleNode>, MerklePath), StateMerkleError> {
        let lcp_path = self.find_longest_prefix(state_key).await?;
        let maybe_lcp_node = self.get_node(&lcp_path).await?;

        // Adding the first node to the merkle trie
        if lcp_path.0.is_empty() && maybe_lcp_node.is_none() {
            return Ok((None, lcp_path));
        }

        let lcp_node = maybe_lcp_node.ok_or(StateMerkleError::MerkleTrieNotInitialized)?;
        Ok((Some(lcp_node), lcp_path))
    }

    fn cache_entry_to_leaf_node_and_state_db_write_set(
        state_key: &StateKey,
        cache_entry: &CacheEntry,
    ) -> Result<(LeafNode, Option<StateDBWrite>), StateMerkleError> {
        let state_key_bv = bits_encode_msb(state_key.as_slice());
        let state_encoded = cache_entry.value.encode()?;
        if state_encoded.len() > HASH_SIZE {
            // Regular Leaf
            let state_hash = hash::<Blake2b256>(state_encoded.as_slice())?;
            Ok((
                LeafNode::new(state_key_bv, LeafNodeData::Regular(state_hash.clone())),
                Some((state_hash, state_encoded)),
            ))
        } else {
            // Embedded Leaf
            Ok((
                LeafNode::new(state_key_bv, LeafNodeData::Embedded(state_encoded)),
                None,
            ))
        }
    }

    /// Converts the given dirty state cache entry into leaf node writes for the `MerkleChangeSet`,
    /// restructuring the internal in-memory structure of the Merkle trie.
    ///
    /// Depending on the kinds of the state mutations, the trie structure is updated differently.
    async fn insert_dirty_cache_entry_as_leaf_writes(
        &mut self,
        state_key: &StateKey,
        dirty_entry: &CacheEntry,
    ) -> Result<(), StateMerkleError> {
        if let CacheEntryStatus::Dirty(state_mut) = &dirty_entry.status {
            match state_mut {
                StateMut::Add => {
                    // For `Add` state mutation, we first need to get the current Merkle node with the
                    // longest common path with the given `state_key` to determine how to update
                    // the trie structure.
                    let (lcp_node, lcp_path) = self.get_longest_common_path_node(state_key).await?;
                    match lcp_node {
                        Some(MerkleNode::Branch(_)) => {
                            // Add case 1. New leaf is extending the single-child branch node.
                            let (leaf, maybe_state_db_write) =
                                Self::cache_entry_to_leaf_node_and_state_db_write_set(
                                    state_key,
                                    dirty_entry,
                                )?;

                            // Extend 1 bit to the lcp path to get the leaf path
                            let leaf_path = MerklePath(
                                bits_encode_msb(state_key.as_slice())[..lcp_path.0.len() + 1]
                                    .to_bitvec(),
                            );

                            self.merkle_change_set.extend_affected_paths(&leaf_path);

                            // Adds 1 merkle node entry to the MerkleChangeSet
                            self.merkle_change_set
                                .insert_node(leaf_path.clone(), Some(MerkleNode::Leaf(leaf)));

                            // Insert the added leaf path to the MerkleChangeSet
                            self.merkle_change_set
                                .insert_leaf_path(state_key.clone(), Some(leaf_path));

                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_change_set.insert_state_db_write(state_db_write);
                            }
                        }
                        Some(MerkleNode::Leaf(sibling_candidate)) => {
                            // Add case 2. New leaf is extending the leaf node,
                            // which will be its sibling after the processing.
                            let (leaf, maybe_state_db_write) =
                                Self::cache_entry_to_leaf_node_and_state_db_write_set(
                                    state_key,
                                    dirty_entry,
                                )?;

                            // Compare state keys of the new leaf node and its sibling candidate
                            // to determine the final merkle path of those two leaves after processing.
                            let sibling_state_key_bv = sibling_candidate.state_key_bv.clone();
                            let new_leaf_state_key_bv = bits_encode_msb(state_key.as_slice());
                            let (sibling_path, new_leaf_path) = derive_final_leaf_paths(
                                sibling_state_key_bv.clone(),
                                new_leaf_state_key_bv,
                            );
                            self.merkle_change_set.extend_affected_paths(&new_leaf_path);
                            self.merkle_change_set
                                .insert_to_affected_paths(sibling_path.clone());

                            // Adds 2 merkle node entries to the MerkleChangeSet
                            let new_leaf_node = MerkleNode::Leaf(leaf.clone());
                            let new_leaf_node_hash = new_leaf_node.hash()?;
                            self.merkle_change_set
                                .insert_node(new_leaf_path.clone(), Some(new_leaf_node));
                            let sibling_node = MerkleNode::Leaf(sibling_candidate.clone());
                            let sibling_node_hash = sibling_node.hash()?;
                            self.merkle_change_set
                                .insert_node(sibling_path.clone(), Some(sibling_node));

                            // Add all new branch node entries to the MerkleChangeSet, from the parent
                            // node of the new leaf and its sibling all the way up to the `lcp_node`.

                            // Initialize
                            let mut branch_path = new_leaf_path.clone();
                            let new_leaf_side = branch_path.0.pop().ok_or(
                                StateMerkleError::InvalidBranchStructure(hex::encode(
                                    branch_path.as_db_key(),
                                )),
                            )?;

                            let (mut left_hash, mut right_hash) = if new_leaf_side {
                                (sibling_node_hash, new_leaf_node_hash)
                            } else {
                                (new_leaf_node_hash, sibling_node_hash)
                            };

                            while branch_path.0.len() >= lcp_path.0.len() {
                                let branch_node =
                                    MerkleNode::Branch(BranchNode::new(&left_hash, &right_hash));
                                let branch_node_hash = branch_node.hash()?;
                                self.merkle_change_set
                                    .insert_node(branch_path.clone(), Some(branch_node));

                                if branch_path.0.is_empty() {
                                    break;
                                }

                                // Update branch_path, left_hash and right_hash for the next loop
                                let branch_sibling_path = branch_path.sibling().ok_or(
                                    StateMerkleError::InvalidBranchStructure(hex::encode(
                                        branch_path.as_db_key(),
                                    )),
                                )?;

                                // Check if a node exists at the branch's sibling position, either in
                                // the MerkleChangeSet or the MerkleDB
                                let sibling_hash = self
                                    .get_node(&branch_sibling_path)
                                    .await?
                                    .map(|node| node.hash())
                                    .transpose()?
                                    .unwrap_or_default();

                                let branch_side = branch_path.0.pop().ok_or(
                                    StateMerkleError::InvalidBranchStructure(hex::encode(
                                        branch_path.as_db_key(),
                                    )),
                                )?;

                                (left_hash, right_hash) = if branch_side {
                                    (sibling_hash, branch_node_hash)
                                } else {
                                    (branch_node_hash, sibling_hash)
                                };
                            }

                            // Insert the added leaf paths to the MerkleChangeSet
                            // The original LCP node (sibling candidate) leaf path will simply be updated
                            self.merkle_change_set
                                .insert_leaf_path(state_key.clone(), Some(new_leaf_path));
                            self.merkle_change_set.insert_leaf_path(
                                StateKey::from_slice(
                                    bits_decode_msb(sibling_state_key_bv).as_slice(),
                                )?,
                                Some(sibling_path),
                            );

                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_change_set.insert_state_db_write(state_db_write);
                            }
                        }
                        None => {
                            // Add case 3. Insert the first node to the trie.
                            let (leaf, maybe_state_db_write) =
                                Self::cache_entry_to_leaf_node_and_state_db_write_set(
                                    state_key,
                                    dirty_entry,
                                )?;

                            let leaf_path = MerklePath::root(); // Insert to the root position
                            self.merkle_change_set.extend_affected_paths(&leaf_path);
                            self.merkle_change_set
                                .insert_node(leaf_path.clone(), Some(MerkleNode::Leaf(leaf)));
                            self.merkle_change_set
                                .insert_leaf_path(state_key.clone(), Some(leaf_path));
                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_change_set.insert_state_db_write(state_db_write);
                            }
                        }
                    }
                }
                StateMut::Update => {
                    let leaf_path = self.get_leaf_path(state_key).await?.ok_or(
                        StateMerkleError::MerklePathUnknownForStateKey(format!("{state_key}")),
                    )?;
                    let (leaf, maybe_state_db_write) =
                        Self::cache_entry_to_leaf_node_and_state_db_write_set(
                            state_key,
                            dirty_entry,
                        )?;
                    // `StateMut::Update` case updates 1 merkle node entry
                    self.merkle_change_set.extend_affected_paths(&leaf_path);
                    self.merkle_change_set
                        .insert_node(leaf_path, Some(MerkleNode::Leaf(leaf)));
                    // Note: the leaf path doesn't change.
                    // No need to insert to `MerkleChangeSet.leaf_paths`

                    if let Some(state_db_write) = maybe_state_db_write {
                        self.merkle_change_set.insert_state_db_write(state_db_write);
                    }
                }
                StateMut::Remove => {
                    let leaf_path = self.get_leaf_path(state_key).await?.ok_or(
                        StateMerkleError::MerklePathUnknownForStateKey(format!("{state_key}")),
                    )?;
                    // Find sibling of the leaf node to be removed
                    // Sibling of a leaf node always exists unless the leaf node is the only node in the trie
                    let sibling_path = leaf_path
                        .sibling()
                        .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;
                    let sibling = self
                        .get_node(&sibling_path)
                        .await?
                        .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;

                    match sibling {
                        MerkleNode::Branch(_) => {
                            // Remove case 1. Sibling of the removing leaf is branch.
                            // Simply mark the leaf node as removed in the StateCache.
                            self.merkle_change_set.extend_affected_paths(&leaf_path);
                            self.merkle_change_set.insert_node(leaf_path, None);

                            // Mark the (state key -> leaf path) pair as removed in the StateCache
                            self.merkle_change_set
                                .insert_leaf_path(state_key.clone(), None);
                        }
                        MerkleNode::Leaf(leaf) => {
                            // Remove case 2. Sibling of the removing leaf is leaf.
                            // Iteratively find the final merkle path of the leaf sibling after the removal.

                            let mut post_sibling_path = sibling_path.clone();
                            post_sibling_path.0.pop();

                            let mut collapsed_branch_paths = vec![];

                            // Iterate to find the sibling's final path, collapsing single-child branches
                            // along the way. The iteration stops when we reach the root or a branch
                            // with two children.
                            while !post_sibling_path.0.is_empty() {
                                let parent_path_slice =
                                    &post_sibling_path.0[..post_sibling_path.0.len() - 1];
                                let post_sibling_parent_path =
                                    MerklePath(parent_path_slice.to_bitvec());

                                // If the parent branch node has a single child, promote once again
                                if let Some(MerkleNode::Branch(_)) =
                                    self.get_node(&post_sibling_parent_path).await?
                                {
                                    // Check whether the parent branch node has a single child or not.
                                    // Since the contents of the parent branch node might not be
                                    // updated yet, we should get children nodes from `MerkleManager`
                                    // rather than simply checking the parent branch node's data.
                                    let mut left = post_sibling_parent_path.clone();
                                    left.0.push(false);
                                    let mut right = post_sibling_parent_path.clone();
                                    right.0.push(true);

                                    let parent_branch_has_single_child =
                                        self.get_node(&left).await?.is_none()
                                            ^ self.get_node(&right).await?.is_none();

                                    if parent_branch_has_single_child {
                                        // The parent is also a single-child branch, so it gets collapsed
                                        collapsed_branch_paths.push(post_sibling_path.clone());
                                        post_sibling_path.0.pop();
                                    } else {
                                        // The parent has other children; promotion stops here
                                        break;
                                    }
                                } else {
                                    // The parent is not a branch or doesn't exist; stop promotion
                                    // This should not happen in regular cases
                                    return Err(StateMerkleError::InvalidBranchStructure(
                                        hex::encode(post_sibling_parent_path.as_db_key()),
                                    ));
                                }
                            }

                            // Mark the original leaf for removal
                            self.merkle_change_set.extend_affected_paths(&leaf_path);
                            self.merkle_change_set.insert_node(leaf_path, None);
                            // Mark the removed node's (state key -> leaf path) pair as removed in the StateCache
                            self.merkle_change_set
                                .insert_leaf_path(state_key.clone(), None);

                            // Mark the sibling at its original path for removal
                            self.merkle_change_set
                                .insert_to_affected_paths(sibling_path.clone());
                            self.merkle_change_set.insert_node(sibling_path, None);
                            // Update the sibling's (state key -> leaf path) pair in the StateCache
                            let sibling_state_key_bv = leaf.state_key_bv.clone();
                            self.merkle_change_set.insert_leaf_path(
                                StateKey::from_slice(
                                    bits_decode_msb(sibling_state_key_bv).as_slice(),
                                )?,
                                Some(post_sibling_path.clone()),
                            );

                            // Mark all the collapsed intermediate branches for removal
                            for path in collapsed_branch_paths {
                                self.merkle_change_set.insert_node(path, None);
                            }

                            // Insert the sibling leaf with its final merkle path
                            self.merkle_change_set
                                .insert_node(post_sibling_path, Some(MerkleNode::Leaf(leaf)));
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn insert_dirty_cache_entries_as_leaf_writes(
        &mut self,
        dirty_entries: &[(StateKey, CacheEntry)],
    ) -> Result<(), StateMerkleError> {
        for (state_key, entry) in dirty_entries {
            self.insert_dirty_cache_entry_as_leaf_writes(state_key, entry)
                .await?;
        }
        Ok(())
    }

    /// Recalculates hashes for affected branch nodes and populates the `DBWriteSet`
    /// with all changes to be committed to the `MerkleDB.nodes`.
    ///
    /// Returns the updated merkle root.
    async fn prepare_merkle_db_node_writes(
        &mut self,
    ) -> Result<Option<MerkleRoot>, StateMerkleError> {
        let affected_paths_sorted = self.merkle_change_set.affected_paths_as_sorted_vec();
        // No affected merkle paths; merkle root remains unchanged.
        if affected_paths_sorted.is_empty() {
            return Ok(None);
        }

        // Iterate on affected merkle nodes from the deepest merkle path up toward the root,
        // populating DB write set entries.
        for affected_path in affected_paths_sorted {
            // Attempt to get node at the given path from the `MerkleChangeSet`
            if let Some(affected_node_write) = self.merkle_change_set.get_node(&affected_path) {
                match affected_node_write {
                    // Mutated leaf nodes or removed nodes
                    Some(MerkleNode::Leaf(_)) | None => {
                        self.merkle_change_set
                            .insert_merkle_db_nodes_write((affected_path, affected_node_write));
                        continue;
                    }
                    // Branch nodes have to be re-computed once again, since their children might have been updated
                    Some(MerkleNode::Branch(_)) => {}
                }
            }

            // Get node at the path either from the latest `MerkleChangeSet` or `MerkleDB`.
            // This should be of branch type, since all mutated leaf nodes must be already present
            // at the `MerkleChangeSet`.
            if let Some(affected_node) = self.get_node(&affected_path).await? {
                if let MerkleNode::Branch(mut affected_branch) = affected_node {
                    // If any of its children is mutated and found in the `StateCache`, update
                    // the child node hash value and then push to the DB write set.
                    let left_child_path = affected_path.clone().left_child().ok_or(
                        StateMerkleError::InvalidBranchStructure(hex::encode(
                            affected_path.as_db_key(),
                        )),
                    )?;
                    let right_child_path = affected_path.clone().right_child().ok_or(
                        StateMerkleError::InvalidBranchStructure(hex::encode(
                            affected_path.as_db_key(),
                        )),
                    )?;
                    if let Some(left_child_write) =
                        self.merkle_change_set.get_node(&left_child_path)
                    {
                        match left_child_write {
                            Some(left_child_mutated) => {
                                affected_branch.update_left(&left_child_mutated.hash()?);
                            }
                            None => {
                                // Replace with zero hash for empty (removed) child
                                affected_branch.update_left(&NodeHash::default());
                            }
                        }
                    }
                    if let Some(right_child_write) =
                        self.merkle_change_set.get_node(&right_child_path)
                    {
                        match right_child_write {
                            Some(right_child_mutated) => {
                                affected_branch.update_right(&right_child_mutated.hash()?);
                            }
                            None => {
                                // Replace with zero hash for empty (removed) child
                                affected_branch.update_right(&NodeHash::default());
                            }
                        }
                    }

                    // Insert the updated branch node to the MerkleChangeSet so parent nodes can
                    // refer to updated versions of nodes from the MerkleChangeSet.
                    self.merkle_change_set.insert_node(
                        affected_path.clone(),
                        Some(MerkleNode::Branch(affected_branch.clone())),
                    );

                    // Insert the updated branch node to the DB write set
                    self.merkle_change_set.insert_merkle_db_nodes_write((
                        affected_path.clone(),
                        Some(MerkleNode::Branch(affected_branch)),
                    ));
                } else {
                    return Err(StateMerkleError::AffectedLeafNotFoundFromMerkleChangeSet);
                }
            } else {
                return Err(StateMerkleError::InvalidAffectedMerklePath);
            }
        }

        // Get the new merkle root with an empty MerklePath as key
        let new_merkle_root = self
            .merkle_change_set
            .get_node(&MerklePath::root())
            .ok_or(StateMerkleError::MissingAffectedMerkleRoot)?
            .ok_or(StateMerkleError::RemovingMerkleRoot)?
            .hash()?;

        Ok(Some(new_merkle_root))
    }

    /// Takes all the updated (state key -> leaf path) relationships from `MerkleChangeSet.leaf_paths` and
    /// moves into `MerkleChangeSet.db_write_set.merkle_db_leaf_paths_write_set`,
    /// so that it can be later committed to `MerkleDB.leaf_paths`.
    ///
    /// Unlike `StateDB` write set which directly stores the write entries into the write set,
    /// write set for `MerkleDB` is first staged at `MerkleChangeSet.leaf_paths` and then converted
    /// in this method call, since that staged mapping context is used during the
    /// `insert_dirty_cache_entry_as_leaf_writes` method call for reorganizing the Merkle trie.
    fn prepare_merkle_db_leaf_paths_writes(&mut self) {
        let leaf_paths_to_write = std::mem::take(&mut self.merkle_change_set.leaf_paths);

        self.merkle_change_set
            .db_write_set
            .merkle_db_leaf_paths_write_set
            .reserve(leaf_paths_to_write.len());

        self.merkle_change_set
            .db_write_set
            .merkle_db_leaf_paths_write_set
            .extend(leaf_paths_to_write);
    }

    /// Prepares write set for `MerkleDB` from the `MerkleChangeSet` entries and stores it into
    /// `MerkleChangeSet.db_write_set`. This should be then transformed to `WriteBatch` for DB batch commitment.
    async fn prepare_merkle_db_writes(&mut self) -> Result<Option<MerkleRoot>, StateMerkleError> {
        // Prepares `MerkleChangeSet.db_write_set.merkle_db_nodes_write_set`
        let new_merkle_root = self.prepare_merkle_db_node_writes().await?;

        // Prepares `MerkleChangeSet.db_write_set.merkle_db_leaf_paths_write_set`
        self.prepare_merkle_db_leaf_paths_writes();

        Ok(new_merkle_root)
    }

    /// Generates a write batch for `MerkleDB` from the provided write sets.
    fn generate_merkle_db_write_batch_from_write_set(
        &mut self,
        nodes_write_set: &[MerkleDBNodesWrite],
        leaf_paths_write_set: &[MerkleDBLeafPathsWrite],
    ) -> Result<MerkleDBWriteBatch, StateMerkleError> {
        let mut merkle_db_write_sets = DBWriteSet {
            state_db_write_set: vec![], // not using this here
            merkle_db_nodes_write_set: nodes_write_set.to_vec(),
            merkle_db_leaf_paths_write_set: leaf_paths_write_set.to_vec(),
        };

        let merkle_db_write_batch = merkle_db_write_sets.generate_merkle_db_write_batch(
            self.merkle_db.nodes_cf_handle()?,
            self.merkle_db.leaf_paths_cf_handle()?,
        )?;
        Ok(merkle_db_write_batch)
    }

    /// Commits the provided write batch into the `MerkleDB`.
    async fn commit_write_batch(
        &self,
        batch: MerkleDBWriteBatch,
        nodes_writes: &[MerkleDBNodesWrite],
        leaf_paths_writes: &[MerkleDBLeafPathsWrite],
    ) -> Result<(), StateMerkleError> {
        self.merkle_db
            .commit_write_batch(batch, nodes_writes, leaf_paths_writes)
            .await
    }

    /// Processes the provided dirty state cache entries into `DBWriteSetWithRoot` ready for later
    /// commitment to DBs.
    pub async fn prepare_dirty_cache_commit(
        &mut self,
        dirty_entries: &[(StateKey, CacheEntry)],
    ) -> Result<Option<DBWriteSetWithRoot>, StateMerkleError> {
        if dirty_entries.is_empty() {
            return Ok(None);
        }

        // Update nodes in `MerkleChangeSet`
        self.insert_dirty_cache_entries_as_leaf_writes(dirty_entries)
            .await?;
        let Some(new_merkle_root) = self.prepare_merkle_db_writes().await? else {
            // Clear the MerkleStateChange
            self.merkle_change_set.clear();
            return Ok(None);
        };

        let state_db_write_set =
            std::mem::take(&mut self.merkle_change_set.db_write_set.state_db_write_set);

        let merkle_db_nodes_write_set = std::mem::take(
            &mut self
                .merkle_change_set
                .db_write_set
                .merkle_db_nodes_write_set,
        );
        let merkle_db_leaf_paths_write_set = std::mem::take(
            &mut self
                .merkle_change_set
                .db_write_set
                .merkle_db_leaf_paths_write_set,
        );

        // Clear the MerkleStateChange
        self.merkle_change_set.clear();

        Ok(Some(DBWriteSetWithRoot {
            new_merkle_root,
            db_write_set: DBWriteSet {
                state_db_write_set,
                merkle_db_nodes_write_set,
                merkle_db_leaf_paths_write_set,
            },
        }))
    }

    pub async fn apply_dirty_cache_commit(
        &mut self,
        prepared: DBWriteSetWithRoot,
    ) -> Result<(), StateMerkleError> {
        let merkle_db_write_batch = self.generate_merkle_db_write_batch_from_write_set(
            &prepared.db_write_set.merkle_db_nodes_write_set,
            &prepared.db_write_set.merkle_db_leaf_paths_write_set,
        )?;

        // Commit the produced write batch into the `MerkleDB`
        self.commit_write_batch(
            merkle_db_write_batch,
            &prepared.db_write_set.merkle_db_nodes_write_set,
            &prepared.db_write_set.merkle_db_leaf_paths_write_set,
        )
        .await?;

        // Update the Merkle root at the DB
        self.merkle_db.update_root(prepared.new_merkle_root);
        Ok(())
    }

    /// Processes the provided dirty state cache entries to change internal structure of the
    /// state merkle trie and commits the changes into the `MerkleDB`.
    /// Then, returns write set for the `StateDB`.
    ///
    /// Used for immediately committing dirty state cache into the DB (and finalizing the block),
    /// skipping the staging phase.
    pub async fn commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
        &mut self,
        dirty_entries: &[(StateKey, CacheEntry)],
    ) -> Result<Vec<StateDBWrite>, StateMerkleError> {
        let Some(prepared) = self.prepare_dirty_cache_commit(dirty_entries).await? else {
            // Merkle trie unchanged
            return Ok(vec![]);
        };

        let state_db_write_set = prepared.db_write_set.state_db_write_set.clone();
        self.apply_dirty_cache_commit(prepared).await?;
        Ok(state_db_write_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::prelude::*;
    use fr_common::{ByteEncodable, NodeHash};
    use fr_state_merkle_v2::{
        merkle_path,
        test_utils::{create_dummy_branch, open_merkle_db},
    };

    #[tokio::test]
    async fn test_get_longest_common_path_node() {
        let merkle_db = open_merkle_db();

        let path_1 = merkle_path![1, 0, 1, 1];
        let path_2 = merkle_path![1, 0, 1, 1, 0];
        let path_3 = merkle_path![1, 0, 1, 1, 0, 0];
        let path_4 = merkle_path![1, 0, 1, 1, 0, 1];
        let path_5 = merkle_path![1, 0, 1, 1, 0, 1, 0, 1, 1];

        let test_node = MerkleNode::Branch(create_dummy_branch(1));

        merkle_db
            .insert_node(&path_1, test_node.clone())
            .await
            .unwrap();
        merkle_db
            .insert_node(&path_2, test_node.clone())
            .await
            .unwrap();
        merkle_db
            .insert_node(&path_3, test_node.clone())
            .await
            .unwrap();
        merkle_db
            .insert_node(&path_4, test_node.clone())
            .await
            .unwrap();
        merkle_db
            .insert_node(&path_5, test_node.clone())
            .await
            .unwrap();

        let merkle_manager = MerkleManager::new(merkle_db);

        let mut state_key_vec = bits_decode_msb(bitvec![u8, Msb0; 1, 0, 1, 1, 0, 0, 1, 1, 1]);
        state_key_vec.resize(31, 0);
        let state_key = StateKey::from_slice(&state_key_vec).unwrap();

        let (_lcp_node, lcp_path) = merkle_manager
            .get_longest_common_path_node(&state_key)
            .await
            .unwrap();
        let expected_path = path_3;
        assert_eq!(lcp_path, expected_path);
    }

    mod merkle_commit_tests {
        use super::*;
        use crate::{state_utils::StateEntryType, types::*};
        use fr_state_merkle_v2::test_utils::{
            create_dummy_regular_leaf, create_dummy_single_child_branch,
            create_state_key_from_path_prefix,
        };

        async fn setup_add_with_lcp_branch() -> (MerkleDB, StateKey, CacheEntry) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1]; // LCP node; single-child branch
            let path_10 = merkle_path![1, 0];
            let path_100 = merkle_path![1, 0, 0];
            let path_101 = merkle_path![1, 0, 1];

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));
            let lcp_node = MerkleNode::Branch(BranchNode::new(
                &NodeHash::from_slice(&[1; 32]).unwrap(),
                &NodeHash::default(), // no right child
            ));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_1, lcp_node).await.unwrap();
            merkle_db.insert_node(&path_10, dummy_branch).await.unwrap();
            merkle_db
                .insert_node(&path_100, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_101, dummy_leaf).await.unwrap();

            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1, 0, 1, 1]);
            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Add);

            (merkle_db, state_key, dirty_cache_entry)
        }

        #[tokio::test]
        async fn test_add_with_lcp_branch_change_set() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_add_with_lcp_branch().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            let expected_added_leaf_merkle_path = merkle_path![1, 1];
            let expected_added_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
            ));

            // Check `MerkleChangeSet.nodes`
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&expected_added_leaf_merkle_path)
                .unwrap();
            assert_eq!(entry, Some(expected_added_leaf_node.clone()));

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 10]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 3);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&expected_added_leaf_merkle_path));

            // Check `MerkleChangeSet.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_add_with_lcp_branch_db_commit() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_add_with_lcp_branch().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);
            let dirty_cache_entries = [(state_key.clone(), dirty_cache_entry.clone())];

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check added leaf
            let added_leaf = merkle_manager.merkle_db.get_leaf(&state_key).await.unwrap();
            assert_eq!(
                added_leaf,
                Some(LeafNode::new(
                    bits_encode_msb(state_key.as_slice()),
                    LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
                ))
            );
        }

        async fn setup_add_with_lcp_leaf() -> (MerkleDB, StateKey, CacheEntry) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // LCP node; leaf

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            // LCP node path: 1100_0011_00...0
            let mut lcp_node_state_key = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0];
            lcp_node_state_key.0.resize(248, false);
            let lcp_node_data = vec![255u8; 20];
            let lcp_node = MerkleNode::Leaf(LeafNode::new(
                lcp_node_state_key.0,
                LeafNodeData::Embedded(lcp_node_data),
            ));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_1, dummy_branch).await.unwrap();
            merkle_db.insert_node(&path_10, dummy_leaf).await.unwrap();
            merkle_db
                .insert_node(&path_11, lcp_node.clone())
                .await
                .unwrap();

            // Added state key: 1100_0110_1000_0...0 (248 bits)
            let state_key =
                create_state_key_from_path_prefix(merkle_path![1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0]);
            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Add);

            (merkle_db, state_key, dirty_cache_entry)
        }

        #[tokio::test]
        async fn test_add_with_lcp_leaf_change_set() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_add_with_lcp_leaf().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Added leaf merkle path should be: 11_0001
            let expected_added_leaf_merkle_path = merkle_path![1, 1, 0, 0, 0, 1];
            let expected_added_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
            ));

            // LCP node path should be updated to: 11_0000
            let expected_lcp_node_final_merkle_path = merkle_path![1, 1, 0, 0, 0, 0];

            // Check `MerkleChangeSet.nodes`
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&expected_added_leaf_merkle_path)
                .unwrap();
            assert_eq!(entry, Some(expected_added_leaf_node));
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&expected_lcp_node_final_merkle_path)
                .unwrap();
            // LCP node path: 1100_0011_00...0
            let mut lcp_node_state_key = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0];
            lcp_node_state_key.0.resize(248, false);
            let lcp_node_data = vec![255u8; 20];
            let lcp_node = MerkleNode::Leaf(LeafNode::new(
                lcp_node_state_key.0,
                LeafNodeData::Embedded(lcp_node_data),
            ));
            assert_eq!(entry, Some(lcp_node));

            // Check new branch nodes are added to `MerkleChangeSet`
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1])
                .unwrap()
                .unwrap()
                .is_branch());

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 11, 110, 1100, 11000, 110000, 110001]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 8);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_add_with_lcp_leaf_db_commit() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_add_with_lcp_leaf().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);
            let dirty_cache_entries = [(state_key.clone(), dirty_cache_entry.clone())];

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check added leaf
            let added_leaf = merkle_manager.merkle_db.get_leaf(&state_key).await.unwrap();
            assert_eq!(
                added_leaf,
                Some(LeafNode::new(
                    bits_encode_msb(state_key.as_slice()),
                    LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
                ))
            );

            // Check updated LCP node
            let original_lcp_path = merkle_path![1, 1];
            let updated_lcp_path = merkle_path![1, 1, 0, 0, 0, 0];
            assert!(merkle_manager
                .merkle_db
                .get_node(&original_lcp_path)
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&updated_lcp_path)
                .await
                .unwrap()
                .is_some());

            // Check added branch nodes
            let path_110 = merkle_path![1, 1, 0];
            let path_1100 = merkle_path![1, 1, 0, 0];
            let path_11000 = merkle_path![1, 1, 0, 0, 0];
            assert!(merkle_manager
                .merkle_db
                .get_node(&path_110)
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&path_1100)
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&path_11000)
                .await
                .unwrap()
                .is_some());
        }

        async fn setup_update() -> (MerkleDB, StateKey, CacheEntry) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // Update this node

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_1, dummy_branch).await.unwrap();
            merkle_db
                .insert_node(&path_10, dummy_leaf.clone())
                .await
                .unwrap();

            // State key of the updated entry: 11... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .insert_leaf(&state_key, path_11, original_leaf)
                .await
                .unwrap();

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Update);

            (merkle_db, state_key, dirty_cache_entry)
        }

        #[tokio::test]
        async fn test_update_change_set() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_update().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Updated leaf merkle path should be: 11
            let updated_leaf_merkle_path = merkle_path![1, 1];

            // Check `MerkleChangeSet.nodes`
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&updated_leaf_merkle_path)
                .unwrap();
            let expected_updated_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
            ));
            assert_eq!(entry, Some(expected_updated_leaf_node));

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 11]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 3);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_update_db_commit() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_update().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);
            let dirty_cache_entries = [(state_key.clone(), dirty_cache_entry.clone())];

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check updated leaf
            let updated_leaf = merkle_manager.merkle_db.get_leaf(&state_key).await.unwrap();
            assert_eq!(
                updated_leaf,
                Some(LeafNode::new(
                    bits_encode_msb(state_key.as_slice()),
                    LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
                ))
            );
        }

        async fn setup_remove_with_branch_sibling() -> (MerkleDB, StateKey, CacheEntry) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // Remove this node
            let path_100 = merkle_path![1, 0, 0];
            let path_101 = merkle_path![1, 0, 1];

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_1, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_10, dummy_branch).await.unwrap();
            merkle_db
                .insert_node(&path_100, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_101, dummy_leaf).await.unwrap();

            // State key of the updated entry: 11... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .insert_leaf(&state_key, path_11, original_leaf)
                .await
                .unwrap();

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Remove);

            (merkle_db, state_key, dirty_cache_entry)
        }

        #[tokio::test]
        async fn test_remove_with_branch_sibling_change_set() {
            let (merkle_db, state_key, dirty_cache_entry) =
                setup_remove_with_branch_sibling().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Removed leaf merkle path should be: 11
            let removed_leaf_merkle_path = merkle_path![1, 1];

            // Check `MerkleChangeSet.nodes`
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&removed_leaf_merkle_path)
                .unwrap();
            assert!(entry.is_none()); // Should be marked as `None`

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 11]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 3);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_with_branch_sibling_db_commit() {
            let (merkle_db, state_key, dirty_cache_entry) =
                setup_remove_with_branch_sibling().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);
            let dirty_cache_entries = [(state_key.clone(), dirty_cache_entry.clone())];

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check removed leaf
            let removed_leaf = merkle_manager.merkle_db.get_leaf(&state_key).await.unwrap();
            assert!(removed_leaf.is_none());
        }

        async fn setup_remove_with_leaf_sibling() -> (MerkleDB, StateKey, CacheEntry) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_101 = merkle_path![1, 0, 1];
            let path_1010 = merkle_path![1, 0, 1, 0];
            let path_1011 = merkle_path![1, 0, 1, 1]; // Remove this node

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_single_child_branch = MerkleNode::Branch(create_dummy_single_child_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));
            let sibling = MerkleNode::Leaf(create_dummy_regular_leaf(255));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_1, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_10, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_101, dummy_branch)
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_1010, sibling.clone())
                .await
                .unwrap();

            // State key of the removed entry: 1011... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .insert_leaf(&state_key, path_1011, original_leaf)
                .await
                .unwrap();

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Remove);

            (merkle_db, state_key, dirty_cache_entry)
        }

        #[tokio::test]
        async fn test_remove_with_leaf_sibling_change_set() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_remove_with_leaf_sibling().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Removed leaf merkle path should be: 1011
            let removed_leaf_merkle_path = merkle_path![1, 0, 1, 1];

            // Check `MerkleChangeSet.nodes`
            let entry = merkle_manager
                .merkle_change_set
                .get_node(&removed_leaf_merkle_path)
                .unwrap();
            assert!(entry.is_none()); // Should be marked as `None`

            // Check removed node entries
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 0])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 0, 1])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 0, 1, 0])
                .unwrap()
                .is_none());

            // Check the updated path entry
            let sibling = MerkleNode::Leaf(create_dummy_regular_leaf(255));
            assert_eq!(
                merkle_manager
                    .merkle_change_set
                    .get_node(&merkle_path![1])
                    .unwrap(),
                Some(sibling)
            );

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 10, 101, 1010, 1011]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 6);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_with_leaf_sibling_db_commit() {
            let (merkle_db, state_key, dirty_cache_entry) = setup_remove_with_leaf_sibling().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);
            let dirty_cache_entries = [(state_key.clone(), dirty_cache_entry.clone())];

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check removed leaf
            let removed_leaf = merkle_manager.merkle_db.get_leaf(&state_key).await.unwrap();
            assert!(removed_leaf.is_none());

            // A node at the original sibling path should be removed
            let removed_original_sibling = merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 0, 1, 0])
                .await
                .unwrap();
            assert!(removed_original_sibling.is_none());

            // Updated sibling node
            let updated_sibling = merkle_manager
                .merkle_db
                .get_node(&merkle_path![1])
                .await
                .unwrap();
            let sibling = MerkleNode::Leaf(create_dummy_regular_leaf(255));
            assert_eq!(updated_sibling, Some(sibling));
        }

        async fn setup_remove_two_adjacent_leaves() -> (MerkleDB, Vec<(StateKey, CacheEntry)>) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_00 = merkle_path![0, 0];
            let path_01 = merkle_path![0, 1];
            let path_10 = merkle_path![1, 0];
            let path_101 = merkle_path![1, 0, 1];
            let path_1010 = merkle_path![1, 0, 1, 0];
            let path_1011 = merkle_path![1, 0, 1, 1];

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_single_child_branch = MerkleNode::Branch(create_dummy_single_child_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_1, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_00, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_01, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_10, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_101, dummy_leaf.clone())
                .await
                .unwrap();

            // State key of the removed entry #1: 1011... (248 bits)
            let state_key_1011 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 1]);
            let state_key_1011_bv = bits_encode_msb(state_key_1011.as_slice());
            let original_leaf_1011 =
                LeafNode::new(state_key_1011_bv, LeafNodeData::Embedded(vec![254u8; 10]));
            merkle_db
                .insert_leaf(&state_key_1011, path_1011, original_leaf_1011)
                .await
                .unwrap();

            // State key of the removed entry #2: 1010... (248 bits)
            let state_key_1010 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 0]);
            let state_key_1010_bv = bits_encode_msb(state_key_1010.as_slice());
            let original_leaf_1010 =
                LeafNode::new(state_key_1010_bv, LeafNodeData::Embedded(vec![255u8; 10]));

            merkle_db
                .insert_leaf(&state_key_1010, path_1010, original_leaf_1010)
                .await
                .unwrap();

            let mut dirty_cache_entry_1011 =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::new(2)));
            dirty_cache_entry_1011.status = CacheEntryStatus::Dirty(StateMut::Remove);

            let mut dirty_cache_entry_1010 =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::new(3)));
            dirty_cache_entry_1010.status = CacheEntryStatus::Dirty(StateMut::Remove);

            let dirty_cache_entries = vec![
                (state_key_1011, dirty_cache_entry_1011),
                (state_key_1010, dirty_cache_entry_1010),
            ];

            (merkle_db, dirty_cache_entries)
        }

        #[tokio::test]
        async fn test_remove_two_adjacent_leaves_change_set() {
            let (merkle_db, dirty_cache_entries) = setup_remove_two_adjacent_leaves().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            merkle_manager
                .insert_dirty_cache_entries_as_leaf_writes(&dirty_cache_entries)
                .await
                .unwrap();

            // Removed leaf merkle path #1 should be: 1011
            let removed_leaf_merkle_path_1011 = merkle_path![1, 0, 1, 1];
            // Removed leaf merkle path #2 should be: 1010
            let removed_leaf_merkle_path_1010 = merkle_path![1, 0, 1, 0];

            // Check `MerkleChangeSet.nodes`
            // Check removed node entries
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 0])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 0, 1])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&removed_leaf_merkle_path_1011)
                .unwrap()
                .is_none());

            assert!(merkle_manager
                .merkle_change_set
                .get_node(&removed_leaf_merkle_path_1010)
                .unwrap()
                .is_none());

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 10, 101, 1010, 1011]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 6);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_two_adjacent_leaves_db_commit() {
            let (merkle_db, dirty_cache_entries) = setup_remove_two_adjacent_leaves().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check removed leaves
            let state_key_1011 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 1]);
            let state_key_1010 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 0]);

            let removed_1011 = merkle_manager
                .merkle_db
                .get_leaf(&state_key_1011)
                .await
                .unwrap();
            let removed_1010 = merkle_manager
                .merkle_db
                .get_leaf(&state_key_1010)
                .await
                .unwrap();

            assert!(removed_1011.is_none());
            assert!(removed_1010.is_none());

            // Check removed branches
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1])
                .await
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 0])
                .await
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 0, 1])
                .await
                .unwrap()
                .is_none());
        }

        async fn setup_add_two_adjacent_leaves() -> (MerkleDB, Vec<(StateKey, CacheEntry)>) {
            let merkle_db = open_merkle_db();

            let root_path = MerklePath::root();
            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // LCP node; leaf

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            // LCP node path: 1100_0011_00...
            let mut lcp_node_state_key_merkle_path = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0];
            lcp_node_state_key_merkle_path.0.resize(248, false);
            let lcp_node_data = vec![255u8; 20];
            let lcp_node = MerkleNode::Leaf(LeafNode::new(
                lcp_node_state_key_merkle_path.0,
                LeafNodeData::Embedded(lcp_node_data),
            ));

            merkle_db
                .insert_node(&root_path, dummy_branch.clone())
                .await
                .unwrap();
            merkle_db
                .insert_node(&path_0, dummy_leaf.clone())
                .await
                .unwrap();
            merkle_db.insert_node(&path_1, dummy_branch).await.unwrap();
            merkle_db.insert_node(&path_10, dummy_leaf).await.unwrap();
            merkle_db
                .insert_node(&path_11, lcp_node.clone())
                .await
                .unwrap();

            // Added state key #1: 1100_0110_10...0 (248 bits)
            let added_state_key_1 =
                create_state_key_from_path_prefix(merkle_path![1, 1, 0, 0, 0, 1, 1, 0, 1, 0]);
            let mut dirty_cache_entry_1 =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::new(1)));
            dirty_cache_entry_1.status = CacheEntryStatus::Dirty(StateMut::Add);

            // Added state key #2: 1100_0111_00...0 (248 bits)
            let added_state_key_2 =
                create_state_key_from_path_prefix(merkle_path![1, 1, 0, 0, 0, 1, 1, 1, 0, 0]);
            let mut dirty_cache_entry_2 =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::new(2)));
            dirty_cache_entry_2.status = CacheEntryStatus::Dirty(StateMut::Add);

            let dirty_cache_entries = vec![
                (added_state_key_1.clone(), dirty_cache_entry_1),
                (added_state_key_2.clone(), dirty_cache_entry_2),
            ];

            (merkle_db, dirty_cache_entries)
        }

        #[tokio::test]
        async fn test_add_two_adjacent_leaves_change_set() {
            let (merkle_db, dirty_cache_entries) = setup_add_two_adjacent_leaves().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            let added_state_key_1 = dirty_cache_entries[0].0.clone();
            let dirty_cache_entry_1 = dirty_cache_entries[0].1.clone();
            let expected_added_leaf_node_1 = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(added_state_key_1.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry_1.value.encode().unwrap()),
            ));

            let added_state_key_2 = dirty_cache_entries[1].0.clone();
            let dirty_cache_entry_2 = dirty_cache_entries[1].1.clone();
            let expected_added_leaf_node_2 = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(added_state_key_2.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry_2.value.encode().unwrap()),
            ));

            // LCP node path: 1100_0011_00...
            let mut lcp_node_state_key_merkle_path = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0];
            lcp_node_state_key_merkle_path.0.resize(248, false);
            let lcp_node_state_key = StateKey::from_slice(
                bits_decode_msb(lcp_node_state_key_merkle_path.0.clone()).as_slice(),
            )
            .unwrap();
            let lcp_node_data = vec![255u8; 20];
            let lcp_node = MerkleNode::Leaf(LeafNode::new(
                lcp_node_state_key_merkle_path.0,
                LeafNodeData::Embedded(lcp_node_data),
            ));

            merkle_manager
                .insert_dirty_cache_entries_as_leaf_writes(&dirty_cache_entries)
                .await
                .unwrap();

            // Added leaf #1 merkle path should be: 1100_0110
            let added_leaf_1_merkle_path = merkle_path![1, 1, 0, 0, 0, 1, 1, 0];
            // Added leaf #2 merkle path should be: 1100_0111
            let added_leaf_2_merkle_path = merkle_path![1, 1, 0, 0, 0, 1, 1, 1];
            // LCP node merkle path should be: 110000
            let lcp_node_merkle_path = merkle_path![1, 1, 0, 0, 0, 0];

            // Check `MerkleChangeSet.nodes`
            let added_leaf_1_from_change_set = merkle_manager
                .merkle_change_set
                .get_node(&added_leaf_1_merkle_path)
                .unwrap();
            assert_eq!(
                added_leaf_1_from_change_set,
                Some(expected_added_leaf_node_1)
            );

            let added_leaf_2_from_change_set = merkle_manager
                .merkle_change_set
                .get_node(&added_leaf_2_merkle_path)
                .unwrap();
            assert_eq!(
                added_leaf_2_from_change_set,
                Some(expected_added_leaf_node_2)
            );

            let lcp_node_from_change_set = merkle_manager
                .merkle_change_set
                .get_node(&lcp_node_merkle_path)
                .unwrap();
            assert_eq!(lcp_node_from_change_set, Some(lcp_node));

            // Check new branch nodes are added to `MerkleChangeSet`
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0, 0, 1, 1])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0, 0, 1])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1, 0])
                .unwrap()
                .unwrap()
                .is_branch());
            assert!(merkle_manager
                .merkle_change_set
                .get_node(&merkle_path![1, 1])
                .unwrap()
                .unwrap()
                .is_branch());

            // Check added / updated leaf paths
            assert_eq!(
                merkle_manager
                    .merkle_change_set
                    .get_leaf_path(&added_state_key_1)
                    .unwrap(),
                Some(added_leaf_1_merkle_path)
            );
            assert_eq!(
                merkle_manager
                    .merkle_change_set
                    .get_leaf_path(&added_state_key_2)
                    .unwrap(),
                Some(added_leaf_2_merkle_path)
            );
            assert_eq!(
                merkle_manager
                    .merkle_change_set
                    .get_leaf_path(&lcp_node_state_key)
                    .unwrap(),
                Some(lcp_node_merkle_path)
            );

            // Check `MerkleChangeSet.affected_paths`
            // affected paths should be: [root, 1, 11, 110, 1100, 11000, 110000, 110001, 1100011, 1100_0110, 1100_0111]
            let affected_paths = merkle_manager.merkle_change_set.affected_paths;
            assert_eq!(affected_paths.len(), 11);
            assert!(affected_paths.contains(&MerklePath::root()));
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1, 1, 1]));

            // Check `MerkleChangeSet.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_change_set
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_add_two_adjacent_leaves_db_commit() {
            let (merkle_db, dirty_cache_entries) = setup_add_two_adjacent_leaves().await;
            let mut merkle_manager = MerkleManager::new(merkle_db);

            let added_state_key_1 = dirty_cache_entries[0].0.clone();
            let dirty_cache_entry_1 = dirty_cache_entries[0].1.clone();
            let expected_added_leaf_1 = LeafNode::new(
                bits_encode_msb(added_state_key_1.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry_1.value.encode().unwrap()),
            );

            let added_state_key_2 = dirty_cache_entries[1].0.clone();
            let dirty_cache_entry_2 = dirty_cache_entries[1].1.clone();
            let expected_added_leaf_2 = LeafNode::new(
                bits_encode_msb(added_state_key_2.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry_2.value.encode().unwrap()),
            );

            // LCP node path: 1100_0011_00...
            let mut lcp_node_state_key_merkle_path = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0];
            lcp_node_state_key_merkle_path.0.resize(248, false);
            let lcp_node_state_key = StateKey::from_slice(
                bits_decode_msb(lcp_node_state_key_merkle_path.0.clone()).as_slice(),
            )
            .unwrap();
            let lcp_node_data = vec![255u8; 20];
            let expected_lcp_leaf = LeafNode::new(
                lcp_node_state_key_merkle_path.0,
                LeafNodeData::Embedded(lcp_node_data),
            );

            let state_db_writes = merkle_manager
                .commit_dirty_state_cache_to_merkle_db_and_produce_state_db_write_set(
                    &dirty_cache_entries,
                )
                .await
                .unwrap();

            assert!(state_db_writes.is_empty()); // No state db writes

            // Check added leaves
            let added_leaf_1 = merkle_manager
                .merkle_db
                .get_leaf(&added_state_key_1)
                .await
                .unwrap();
            let added_leaf_2 = merkle_manager
                .merkle_db
                .get_leaf(&added_state_key_2)
                .await
                .unwrap();
            let lcp_leaf = merkle_manager
                .merkle_db
                .get_leaf(&lcp_node_state_key)
                .await
                .unwrap();

            assert_eq!(added_leaf_1, Some(expected_added_leaf_1));
            assert_eq!(added_leaf_2, Some(expected_added_leaf_2));
            assert_eq!(lcp_leaf, Some(expected_lcp_leaf));

            // Check added branches
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1])
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1, 0])
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1, 0, 0])
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1, 0, 0, 0])
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1, 0, 0, 0, 1])
                .await
                .unwrap()
                .is_some());
            assert!(merkle_manager
                .merkle_db
                .get_node(&merkle_path![1, 1, 0, 0, 0, 1, 1])
                .await
                .unwrap()
                .is_some());
        }
    }
}
