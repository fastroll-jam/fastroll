use crate::{
    merkle_cache::{MerkleCache, StateDBWrite},
    merkle_db::MerkleDB,
    types::{LeafNode, LeafNodeData, MerkleNode, MerklePath, StateMerkleError},
    utils::{bits_decode_msb, bits_encode_msb, derive_final_leaf_paths},
};
use fr_codec::prelude::*;
use fr_common::{ByteEncodable, StateKey, HASH_SIZE};
use fr_crypto::{hash, Blake2b256};
use fr_state::cache::{CacheEntry, CacheEntryStatus, StateMut};

pub(crate) struct MerkleManager {
    merkle_db: MerkleDB,
    merkle_cache: MerkleCache,
}

impl MerkleManager {
    pub fn new(merkle_db: MerkleDB, merkle_cache: MerkleCache) -> Self {
        Self {
            merkle_db,
            merkle_cache,
        }
    }

    /// Gets a merkle node with the longest common path with the given state key found from the MerkleDB.
    async fn get_longest_common_path_node(
        &self,
        state_key: &StateKey,
    ) -> Result<(MerkleNode, MerklePath), StateMerkleError> {
        let lcp_path = self
            .merkle_db
            .find_longest_prefix(state_key)
            .await?
            .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;
        let lcp_node = self
            .merkle_db
            .get(&lcp_path)
            .await?
            .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;
        Ok((lcp_node, lcp_path))
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

    async fn insert_dirty_cache_entry_as_leaf_writes(
        &mut self,
        state_key: &StateKey,
        dirty_entry: &CacheEntry,
    ) -> Result<(), StateMerkleError> {
        if let CacheEntryStatus::Dirty(state_mut) = &dirty_entry.status {
            match state_mut {
                StateMut::Add => {
                    let (lcp_node, lcp_path) = self.get_longest_common_path_node(state_key).await?;
                    println!(">>> lcp_node: {lcp_node:?}, lcp_path: {lcp_path:?}");
                    match lcp_node {
                        MerkleNode::Branch(_) => {
                            // New leaf is extending the single-child branch node
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

                            self.merkle_cache.extend_affected_paths(&leaf_path);

                            // Adds 1 merkle node entry to the MerkleCache
                            self.merkle_cache
                                .insert_node(leaf_path.clone(), Some(MerkleNode::Leaf(leaf)));

                            // Insert the added leaf path to the MerkleCache
                            self.merkle_cache
                                .insert_leaf_path(state_key.clone(), Some(leaf_path));

                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_cache.insert_state_db_write(state_db_write);
                            }
                        }
                        MerkleNode::Leaf(sibling_candidate) => {
                            println!(">>> sibling_candidate (lcp node): {sibling_candidate:?}");
                            // New leaf is extending the leaf node, which will be its sibling in the post state
                            let (leaf, maybe_state_db_write) =
                                Self::cache_entry_to_leaf_node_and_state_db_write_set(
                                    state_key,
                                    dirty_entry,
                                )?;

                            // Compare state keys of the new leaf node and its sibling candidate
                            // to determine merkle path of those two leaves in the post state.
                            let sibling_state_key_bv = sibling_candidate.state_key_bv.clone();
                            let new_leaf_state_key_bv = bits_encode_msb(state_key.as_slice());
                            let (sibling_path, new_leaf_path) = derive_final_leaf_paths(
                                sibling_state_key_bv.clone(),
                                new_leaf_state_key_bv,
                            );
                            self.merkle_cache.extend_affected_paths(&new_leaf_path);
                            self.merkle_cache
                                .insert_to_affected_paths(sibling_path.clone());

                            // Adds 2 merkle node entries to the MerkleCache
                            self.merkle_cache
                                .insert_node(new_leaf_path.clone(), Some(MerkleNode::Leaf(leaf)));
                            self.merkle_cache.insert_node(
                                sibling_path.clone(),
                                Some(MerkleNode::Leaf(sibling_candidate)),
                            );

                            // Insert the added leaf paths to the MerkleCache
                            // The original LCP node (sibling candidate) leaf path will simply be updated
                            self.merkle_cache
                                .insert_leaf_path(state_key.clone(), Some(new_leaf_path));
                            self.merkle_cache.insert_leaf_path(
                                StateKey::from_slice(
                                    bits_decode_msb(sibling_state_key_bv).as_slice(),
                                )?,
                                Some(sibling_path),
                            );

                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_cache.insert_state_db_write(state_db_write);
                            }
                        }
                    }
                }
                StateMut::Update => {
                    let leaf_path = self.merkle_db.get_leaf_path(state_key).await?.ok_or(
                        StateMerkleError::MerklePathUnknownForStateKey(format!("{state_key}")),
                    )?;
                    let (leaf, maybe_state_db_write) =
                        Self::cache_entry_to_leaf_node_and_state_db_write_set(
                            state_key,
                            dirty_entry,
                        )?;
                    // `StateMut::Update` case updates 1 merkle node entry
                    self.merkle_cache.extend_affected_paths(&leaf_path);
                    let _ = self
                        .merkle_cache
                        .insert_node(leaf_path, Some(MerkleNode::Leaf(leaf)));
                    // Note: the leaf path doesn't change.
                    // No need to insert to `MerkleCache.leaf_paths`

                    if let Some(state_db_write) = maybe_state_db_write {
                        self.merkle_cache.insert_state_db_write(state_db_write);
                    }
                }
                StateMut::Remove => {
                    let leaf_path = self.merkle_db.get_leaf_path(state_key).await?.ok_or(
                        StateMerkleError::MerklePathUnknownForStateKey(format!("{state_key}")),
                    )?;
                    // Find sibling of the leaf node to be removed
                    // Sibling of a leaf node always exists unless the leaf node is the only node in the trie
                    let sibling_path = leaf_path
                        .sibling()
                        .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;
                    let sibling = self
                        .merkle_db
                        .get(&sibling_path)
                        .await?
                        .ok_or(StateMerkleError::MerkleTrieNotInitialized)?;

                    match sibling {
                        MerkleNode::Branch(_) => {
                            // Sibling of the removing leaf is branch
                            // Simply mark the leaf node as removed in the StateCache
                            self.merkle_cache.extend_affected_paths(&leaf_path);
                            let _ = self.merkle_cache.insert_node(leaf_path, None);

                            // Mark the (state key -> leaf path) pair as removed in the StateCache
                            self.merkle_cache.insert_leaf_path(state_key.clone(), None);
                        }
                        MerkleNode::Leaf(leaf) => {
                            // Sibling of the removing leaf is leaf
                            // Iteratively find the final merkle path of the leaf sibling after the removal

                            let mut post_sibling_path = sibling_path.clone();
                            post_sibling_path.0.pop();

                            let mut collapsed_branch_paths = vec![];

                            // Iterate to find the sibling's final path, collapsing single-child branches
                            // along the way. The iteration stops when we reach the root or a branch
                            // with two children.
                            while !post_sibling_path.0.is_empty() {
                                let parent_path_slice =
                                    &post_sibling_path.0[..post_sibling_path.0.len() - 1];
                                let parent_merkle_path = MerklePath(parent_path_slice.to_bitvec());

                                // If the parent branch node has a single child, promote once again
                                if let Some(MerkleNode::Branch(parent_branch)) =
                                    self.merkle_db.get(&parent_merkle_path).await?
                                {
                                    if parent_branch.has_single_child() {
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
                                    break;
                                }
                            }

                            // Mark the original leaf for removal
                            self.merkle_cache.extend_affected_paths(&leaf_path);
                            let _ = self.merkle_cache.insert_node(leaf_path, None);
                            // Mark the removed node's (state key -> leaf path) pair as removed in the StateCache
                            self.merkle_cache.insert_leaf_path(state_key.clone(), None);

                            // Mark the sibling at its original path for removal
                            self.merkle_cache
                                .insert_to_affected_paths(sibling_path.clone());
                            let _ = self.merkle_cache.insert_node(sibling_path.clone(), None);
                            // Update the sibling's (state key -> leaf path) pair in the StateCache
                            let sibling_state_key_bv = leaf.state_key_bv.clone();
                            self.merkle_cache.insert_leaf_path(
                                StateKey::from_slice(
                                    bits_decode_msb(sibling_state_key_bv).as_slice(),
                                )?,
                                Some(sibling_path),
                            );

                            // Mark all the collapsed intermediate branches for removal
                            for path in collapsed_branch_paths {
                                let _ = self.merkle_cache.insert_node(path, None);
                            }

                            // Insert the sibling leaf with its final merkle path
                            let _ = self
                                .merkle_cache
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
}

// TODO: check `MerkleCache.leaf_paths`
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle_path,
        test_utils::{create_dummy_branch, open_merkle_db},
        utils::bits_decode_msb,
    };
    use bitvec::prelude::*;
    use fr_common::{ByteEncodable, NodeHash};

    #[tokio::test]
    async fn test_get_longest_common_path_node() {
        let merkle_db = open_merkle_db();

        let path_1 = merkle_path![1, 0, 1, 1];
        let path_2 = merkle_path![1, 0, 1, 1, 0];
        let path_3 = merkle_path![1, 0, 1, 1, 0, 0];
        let path_4 = merkle_path![1, 0, 1, 1, 0, 1];
        let path_5 = merkle_path![1, 0, 1, 1, 0, 1, 0, 1, 1];

        let test_node = MerkleNode::Branch(create_dummy_branch(1));

        merkle_db.put(&path_1, test_node.clone()).await.unwrap();
        merkle_db.put(&path_2, test_node.clone()).await.unwrap();
        merkle_db.put(&path_3, test_node.clone()).await.unwrap();
        merkle_db.put(&path_4, test_node.clone()).await.unwrap();
        merkle_db.put(&path_5, test_node.clone()).await.unwrap();

        let merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

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

    mod dirty_cache_entry_tests {
        use super::*;
        use crate::{test_utils::*, types::*};
        use fr_state::{state_utils::StateEntryType, types::Timeslot};

        #[tokio::test]
        async fn test_add_lcp_node_is_branch() {
            let merkle_db = open_merkle_db();

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

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_1, lcp_node).await.unwrap();
            merkle_db.put(&path_10, dummy_branch).await.unwrap();
            merkle_db.put(&path_100, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_101, dummy_leaf).await.unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1, 0, 1, 1]);
            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Add);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            let expected_added_leaf_merkle_path = merkle_path![1, 1];
            let expected_added_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
            ));

            // Check `MerkleCache.nodes`
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&expected_added_leaf_merkle_path)
                .unwrap();
            assert_eq!(*entry, Some(expected_added_leaf_node));

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 10
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 2);
            assert!(affected_paths.contains(&path_1));
            assert!(affected_paths.contains(&expected_added_leaf_merkle_path));

            // Check `MerkleCache.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_add_lcp_node_is_leaf() {
            let merkle_db = open_merkle_db();

            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // LCP node; leaf

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            // LCP node path: 1100_0011_0000
            let mut lcp_node_state_key = merkle_path![1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0];
            lcp_node_state_key.0.resize(248, false);
            let lcp_node_data = vec![255u8; 20];
            let lcp_node = MerkleNode::Leaf(LeafNode::new(
                lcp_node_state_key.0,
                LeafNodeData::Embedded(lcp_node_data),
            ));

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_1, dummy_branch).await.unwrap();
            merkle_db.put(&path_10, dummy_leaf).await.unwrap();
            merkle_db.put(&path_11, lcp_node.clone()).await.unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            // Added state key: 1100_0110_1000_0...0 (248 bits)
            let state_key =
                create_state_key_from_path_prefix(merkle_path![1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0]);
            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Add);

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

            // Check `MerkleCache.nodes`
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&expected_added_leaf_merkle_path)
                .unwrap();
            assert_eq!(*entry, Some(expected_added_leaf_node));
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&expected_lcp_node_final_merkle_path)
                .unwrap();
            assert_eq!(*entry, Some(lcp_node));

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 11, 110, 1100, 11000, 110000, 110001
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 7);
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 1, 0, 0, 0, 1]));

            // TODO: test with regular leaves
            // Check `MerkleCache.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_update() {
            let merkle_db = open_merkle_db();

            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // Update this node

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_1, dummy_branch).await.unwrap();
            merkle_db.put(&path_10, dummy_leaf.clone()).await.unwrap();

            // State key of the updated entry: 11... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .put_leaf(&state_key, path_11, original_leaf)
                .await
                .unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Update);
            let expected_updated_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(dirty_cache_entry.value.encode().unwrap()),
            ));

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Updated leaf merkle path is: 11
            let updated_leaf_merkle_path = merkle_path![1, 1];

            // Check `MerkleCache.nodes`
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&updated_leaf_merkle_path)
                .unwrap();
            assert_eq!(*entry, Some(expected_updated_leaf_node));

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 11
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 2);
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));

            // Check `MerkleCache.db_write_set`
            // Embedded leaf; no db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_sibling_is_branch() {
            let merkle_db = open_merkle_db();

            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1];
            let path_10 = merkle_path![1, 0];
            let path_11 = merkle_path![1, 1]; // Remove this node
            let path_100 = merkle_path![1, 0, 0];
            let path_101 = merkle_path![1, 0, 1];

            let dummy_branch = MerkleNode::Branch(create_dummy_branch(1));
            let dummy_leaf = MerkleNode::Leaf(create_dummy_regular_leaf(1));

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_1, dummy_branch.clone()).await.unwrap();
            merkle_db.put(&path_10, dummy_branch).await.unwrap();
            merkle_db.put(&path_100, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_101, dummy_leaf).await.unwrap();

            // State key of the updated entry: 11... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .put_leaf(&state_key, path_11, original_leaf)
                .await
                .unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Remove);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Removed leaf merkle path is: 11
            let removed_leaf_merkle_path = merkle_path![1, 1];

            // Check `MerkleCache.nodes`
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&removed_leaf_merkle_path)
                .unwrap();
            assert!(entry.is_none()); // Should be marked as `None`

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 11
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 2);
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 1]));

            // Check `MerkleCache.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_sibling_is_leaf() {
            let merkle_db = open_merkle_db();

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

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db
                .put(&path_1, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db
                .put(&path_10, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db.put(&path_101, dummy_branch).await.unwrap();
            merkle_db.put(&path_1010, sibling.clone()).await.unwrap();

            // State key of the removed entry: 1011... (248 bits)
            let state_key = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 1]);
            let original_leaf = create_dummy_regular_leaf(1);
            merkle_db
                .put_leaf(&state_key, path_1011, original_leaf)
                .await
                .unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            let mut dirty_cache_entry =
                CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            dirty_cache_entry.status = CacheEntryStatus::Dirty(StateMut::Remove);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &dirty_cache_entry)
                .await
                .unwrap();

            // Removed leaf merkle path is: 1011
            let removed_leaf_merkle_path = merkle_path![1, 0, 1, 1];

            // Check `MerkleCache.nodes`
            let entry = merkle_manager
                .merkle_cache
                .nodes
                .get(&removed_leaf_merkle_path)
                .unwrap();
            assert!(entry.is_none()); // Should be marked as `None`

            // Check removed node entries
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1, 0])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1, 0, 1])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1, 0, 1, 0])
                .unwrap()
                .is_none());

            // Check the updated path entry
            assert_eq!(
                merkle_manager
                    .merkle_cache
                    .nodes
                    .get(&merkle_path![1])
                    .cloned()
                    .unwrap(),
                Some(sibling)
            );

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 10, 101, 1010, 1011
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 5);
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 1]));

            // Check `MerkleCache.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }

        #[tokio::test]
        async fn test_remove_two_adjacent_leaves() {
            let merkle_db = open_merkle_db();

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

            merkle_db.put(&path_0, dummy_branch.clone()).await.unwrap();
            merkle_db
                .put(&path_1, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db.put(&path_00, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_01, dummy_leaf.clone()).await.unwrap();
            merkle_db
                .put(&path_10, dummy_single_child_branch.clone())
                .await
                .unwrap();
            merkle_db.put(&path_101, dummy_leaf.clone()).await.unwrap();

            // State key of the removed entry #1: 1011... (248 bits)
            let state_key_1011 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 1]);
            let original_leaf_1011 = create_dummy_regular_leaf(2);
            merkle_db
                .put_leaf(&state_key_1011, path_1011, original_leaf_1011)
                .await
                .unwrap();

            // State key of the removed entry #1: 1010... (248 bits)
            let state_key_1010 = create_state_key_from_path_prefix(merkle_path![1, 0, 1, 0]);
            let original_leaf_1010 = create_dummy_regular_leaf(3);
            merkle_db
                .put_leaf(&state_key_1010, path_1010, original_leaf_1010)
                .await
                .unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

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

            merkle_manager
                .insert_dirty_cache_entries_as_leaf_writes(&dirty_cache_entries)
                .await
                .unwrap();

            // Removed leaf merkle path #1 is: 1011
            let removed_leaf_merkle_path_1011 = merkle_path![1, 0, 1, 1];
            // Removed leaf merkle path #2 is: 1010
            let removed_leaf_merkle_path_1010 = merkle_path![1, 0, 1, 0];

            // Check `MerkleCache.nodes`
            // Check removed node entries
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1])
                .unwrap()
                .is_none()); // FIXME: This should be none
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1, 0])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&merkle_path![1, 0, 1])
                .unwrap()
                .is_none());
            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&removed_leaf_merkle_path_1011)
                .unwrap()
                .is_none());

            assert!(merkle_manager
                .merkle_cache
                .nodes
                .get(&removed_leaf_merkle_path_1010)
                .unwrap()
                .is_none());

            // Check `MerkleCache.affected_paths`
            // affected paths should be: 1, 10, 101, 1010, 1011
            let affected_paths = merkle_manager.merkle_cache.affected_paths;
            assert_eq!(affected_paths.len(), 5);
            assert!(affected_paths.contains(&merkle_path![1]));
            assert!(affected_paths.contains(&merkle_path![1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 0]));
            assert!(affected_paths.contains(&merkle_path![1, 0, 1, 1]));

            // Check `MerkleCache.db_write_set`
            // No db write set
            assert!(merkle_manager
                .merkle_cache
                .db_write_set
                .state_db_write_set
                .is_empty());
        }
    }
}
