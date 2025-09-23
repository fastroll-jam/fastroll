use crate::{
    merkle_cache::{MerkleCache, StateDBWrite},
    merkle_db::MerkleDB,
    types::{LeafNode, LeafNodeData, MerkleNode, MerklePath, StateMerkleError},
    utils::{bits_encode_msb, derive_final_leaf_paths},
};
use fr_codec::prelude::*;
use fr_common::{StateKey, HASH_SIZE};
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

    async fn insert_dirty_cache_entry_as_leaf_writes(
        &mut self,
        state_key: &StateKey,
        dirty_entry: &CacheEntry,
    ) -> Result<(), StateMerkleError> {
        if let CacheEntryStatus::Dirty(state_mut) = &dirty_entry.status {
            match state_mut {
                StateMut::Add => {
                    let (lcp_node, lcp_path) = self.get_longest_common_path_node(state_key).await?;
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
                                .insert(leaf_path, Some(MerkleNode::Leaf(leaf)));

                            if let Some(state_db_write) = maybe_state_db_write {
                                self.merkle_cache.insert_state_db_write(state_db_write);
                            }
                        }
                        MerkleNode::Leaf(sibling_candidate) => {
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
                                sibling_state_key_bv,
                                new_leaf_state_key_bv,
                            );
                            self.merkle_cache.extend_affected_paths(&new_leaf_path);
                            self.merkle_cache
                                .insert_to_affected_paths(sibling_path.clone());

                            // Adds 2 merkle node entries to the MerkleCache
                            self.merkle_cache
                                .insert(new_leaf_path, Some(MerkleNode::Leaf(leaf)));
                            self.merkle_cache
                                .insert(sibling_path, Some(MerkleNode::Leaf(sibling_candidate)));

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
                        .insert(leaf_path, Some(MerkleNode::Leaf(leaf)));
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
                            let _ = self.merkle_cache.insert(leaf_path, None);
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
                            let _ = self.merkle_cache.insert(leaf_path, None);

                            // Mark the sibling at its original path for removal
                            self.merkle_cache
                                .insert_to_affected_paths(sibling_path.clone());
                            let _ = self.merkle_cache.insert(sibling_path, None);

                            // Mark all the collapsed intermediate branches for removal
                            for path in collapsed_branch_paths {
                                let _ = self.merkle_cache.insert(path, None);
                            }

                            // Insert the sibling leaf with its final merkle path
                            let _ = self
                                .merkle_cache
                                .insert(post_sibling_path, Some(MerkleNode::Leaf(leaf)));
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

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

        let test_node = create_dummy_branch(1);

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
        async fn test_add_branch_lcp_node() {
            let merkle_db = open_merkle_db();

            let path_0 = merkle_path![0];
            let path_1 = merkle_path![1]; // LCP node; single-child branch
            let path_10 = merkle_path![1, 0];
            let path_100 = merkle_path![1, 0, 0];
            let path_101 = merkle_path![1, 0, 1];

            let dummy_branch = create_dummy_branch(1);
            let dummy_leaf = create_dummy_regular_leaf(1);
            let single_child_branch = MerkleNode::Branch(BranchNode::new(
                &NodeHash::from_slice(&[1; 32]).unwrap(),
                &NodeHash::default(), // no right child
            ));

            merkle_db.put(&path_0, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_1, single_child_branch).await.unwrap();
            merkle_db.put(&path_10, dummy_branch).await.unwrap();
            merkle_db.put(&path_100, dummy_leaf.clone()).await.unwrap();
            merkle_db.put(&path_101, dummy_leaf).await.unwrap();

            let mut merkle_manager = MerkleManager::new(merkle_db, MerkleCache::default());

            let state_key_path_prefix = merkle_path![1, 1, 0, 1, 1];
            let state_key = create_state_key_from_path_prefix(state_key_path_prefix);
            let mut cache_entry = CacheEntry::new(StateEntryType::Timeslot(Timeslot::default()));
            cache_entry.status = CacheEntryStatus::Dirty(StateMut::Add);

            merkle_manager
                .insert_dirty_cache_entry_as_leaf_writes(&state_key, &cache_entry)
                .await
                .unwrap();

            let expected_added_leaf_merkle_path = merkle_path![1, 1];
            let expected_added_leaf_node = MerkleNode::Leaf(LeafNode::new(
                bits_encode_msb(state_key.as_slice()),
                LeafNodeData::Embedded(cache_entry.value.encode().unwrap()),
            ));

            // Check `MerkleCache.map`
            let entry = merkle_manager
                .merkle_cache
                .map
                .get(&expected_added_leaf_merkle_path)
                .unwrap();
            assert_eq!(*entry, Some(expected_added_leaf_node));

            // Check `MerkleCache.affected_paths`
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
    }
}
