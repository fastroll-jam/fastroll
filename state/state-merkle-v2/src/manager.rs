use crate::{
    merkle_cache::{MerkleCache, StateDBWrite},
    merkle_db::MerkleDB,
    types::{LeafNode, LeafNodeData, MerkleNode, StateMerkleError},
    utils::bits_encode_msb,
};
use fr_codec::prelude::*;
use fr_common::{StateKey, HASH_SIZE};
use fr_crypto::{hash, Blake2b256};
use fr_state::cache::{CacheEntry, CacheEntryStatus, StateMut};
use futures::future::join_all;

pub(crate) struct MerkleManager {
    merkle_db: MerkleDB,
    merkle_cache: MerkleCache,
}

impl MerkleManager {
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

    async fn insert_dirty_cache_entries_as_db_writes(
        &self,
        dirty_entries: &[(StateKey, CacheEntry)],
    ) -> Result<(), StateMerkleError> {
        let futures = dirty_entries
            .iter()
            .map(|(state_key, entry)| self.insert_dirty_cache_entry_as_db_write(state_key, entry));
        let results = join_all(futures).await;
        results.into_iter().collect()
    }

    async fn insert_dirty_cache_entry_as_db_write(
        &self,
        state_key: &StateKey,
        dirty_entry: &CacheEntry,
    ) -> Result<(), StateMerkleError> {
        if let CacheEntryStatus::Dirty(state_mut) = &dirty_entry.status {
            match state_mut {
                StateMut::Add => {}
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
                    let _replaced = self.merkle_cache.insert(leaf_path, MerkleNode::Leaf(leaf));
                    if let Some(state_db_write) = maybe_state_db_write {
                        self.merkle_cache.insert_state_db_write(state_db_write);
                    }
                }
                StateMut::Remove => {}
            }
        }
        Ok(())
    }
}
