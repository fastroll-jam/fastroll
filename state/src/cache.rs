use crate::{
    error::StateManagerError,
    state_utils::{StateComponent, StateEntryType},
};
use fr_codec::prelude::*;
use fr_common::StateKey;
use fr_state_merkle::merkle_db::MerkleWriteOp;
use mini_moka::sync::{Cache, ConcurrentCacheExt};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq)]
pub enum StateMut {
    Add,
    Update,
    Remove,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CacheEntryStatus {
    Clean,
    Dirty(StateMut),
}

// FIXME: visibility
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached snapshot of clean state entry, synchronized with the DB.
    pub(crate) clean_snapshot: Arc<StateEntryType>,
    /// Latest state cache entry value.
    pub(crate) value: Arc<StateEntryType>,
    /// State cache status (Clean or Dirty).
    pub(crate) status: CacheEntryStatus,
}

impl CacheEntry {
    pub fn new(value: StateEntryType) -> Self {
        let value = Arc::new(value);
        Self {
            clean_snapshot: value.clone(),
            value,
            status: CacheEntryStatus::Clean,
        }
    }

    pub(crate) fn is_dirty(&self) -> bool {
        matches!(self.status, CacheEntryStatus::Dirty(_))
    }

    pub(crate) fn as_merkle_write_op(
        &self,
        state_key: &StateKey,
    ) -> Result<MerkleWriteOp, StateManagerError> {
        let CacheEntryStatus::Dirty(op) = &self.status else {
            return Err(StateManagerError::NotDirtyCache);
        };

        let encoded = self.value.encode()?;
        let merkle_state_mut = match op {
            StateMut::Add => MerkleWriteOp::Add(state_key.clone(), encoded),
            StateMut::Update => MerkleWriteOp::Update(state_key.clone(), encoded),
            StateMut::Remove => MerkleWriteOp::Remove(state_key.clone()),
        };

        Ok(merkle_state_mut)
    }

    fn mark_dirty(&mut self, state_mut: StateMut) {
        self.status = CacheEntryStatus::Dirty(state_mut);
    }

    fn revert_to_clean(&mut self) {
        self.value = self.clean_snapshot.clone();
        self.status = CacheEntryStatus::Clean;
    }

    pub fn mark_clean_and_snapshot(&mut self) {
        self.status = CacheEntryStatus::Clean;
        self.clean_snapshot = self.value.clone(); // snapshot clean value
    }
}

/// A thread-safe mapping from state keys to their corresponding cache entries.
pub struct StateCache {
    /// A state cache which ensures that dirty cache entries never get evicted.
    inner: Cache<StateKey, CacheEntry>,
    /// Tracks state keys of all "dirty" cache entries.
    dirty_keys: Mutex<HashSet<StateKey>>,
}

impl StateCache {
    /// Creates a `StateCache` with the given max capacity.
    /// Cache entries with `Dirty` status never gets evicted since they have zero weight.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Cache::builder()
                .weigher(|_key, entry: &CacheEntry| -> u32 { u32::from(!entry.is_dirty()) })
                .max_capacity(max_capacity as u64)
                .build(),
            dirty_keys: Mutex::new(HashSet::new()),
        }
    }

    fn get_dirty_state_keys(&self) -> Vec<StateKey> {
        self.dirty_keys.lock().unwrap().iter().cloned().collect()
    }

    fn insert_to_dirty_state_key_set(&self, state_key: StateKey) {
        self.dirty_keys.lock().unwrap().insert(state_key);
    }

    fn remove_dirty_state_key(&self, state_key: &StateKey) {
        self.dirty_keys.lock().unwrap().remove(state_key);
    }

    fn clear_dirty_state_keys(&self) {
        self.dirty_keys.lock().unwrap().clear();
    }

    pub(crate) fn get_entry(&self, key: &StateKey) -> Option<CacheEntry> {
        self.inner.get(key)
    }

    pub(crate) fn get_entry_status(&self, key: &StateKey) -> Option<CacheEntryStatus> {
        self.inner.get(key).map(|entry| entry.status.clone())
    }

    pub(crate) fn get_entry_as_merkle_write_op(
        &self,
        key: &StateKey,
    ) -> Result<MerkleWriteOp, StateManagerError> {
        let entry = self
            .get_entry(key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;
        entry.as_merkle_write_op(key)
    }

    pub(crate) fn insert_entry(&self, key: StateKey, entry: CacheEntry) {
        if entry.is_dirty() {
            self.insert_to_dirty_state_key_set(key.clone());
        }
        self.inner.insert(key, entry);
    }

    // Note: test-only
    pub(crate) fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    pub(crate) fn with_mut_entry<T, F, E>(
        &self,
        state_key: &StateKey,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: StateComponent,
        F: FnOnce(&mut T) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        // Cloned data
        let mut cache_entry = self
            .inner
            .get(state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        let entry_mut = T::from_entry_type_mut(Arc::make_mut(&mut cache_entry.value))
            .ok_or(StateManagerError::UnexpectedEntryType)?;

        f(entry_mut)?; // Call the closure to apply the state mutation

        // If cache entry is dirty with `StateMut::Add` and the new `state_mut` is `StateMut::Update`,
        // keep the entry marked with `StateMut::Add`. This allows mutating new entries before
        // they get committed to the db.
        if cache_entry.status != CacheEntryStatus::Dirty(StateMut::Add)
            || state_mut != StateMut::Update
        {
            self.insert_to_dirty_state_key_set(state_key.clone());
            cache_entry.mark_dirty(state_mut)
        }

        self.inner.insert(state_key.clone(), cache_entry);
        Ok(())
    }

    pub(crate) fn mark_entry_clean_and_snapshot(
        &self,
        key: &StateKey,
    ) -> Result<(), StateManagerError> {
        let mut cache_entry = self
            .inner
            .get(key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;
        cache_entry.mark_clean_and_snapshot();
        self.remove_dirty_state_key(key);
        self.inner.insert(key.clone(), cache_entry);
        Ok(())
    }

    pub(crate) fn collect_dirty(&self) -> Vec<(StateKey, CacheEntry)> {
        let dirty_keys = self.get_dirty_state_keys();
        dirty_keys
            .into_iter()
            .filter_map(|key| self.get_entry(&key).map(|entry| (key, entry)))
            .collect()
    }

    /// Syncs up the state cache with the global state, by removing cache entries that are deleted
    /// from the global state and marking added or updated entries as clean.
    pub(crate) fn sync_cache_status(&self, dirty_entries: &[(StateKey, CacheEntry)]) {
        for (key, entry) in dirty_entries.iter() {
            // Remove cache entries that are removed from the global state
            if let CacheEntryStatus::Dirty(StateMut::Remove) = entry.status {
                self.inner.invalidate(key);
            } else if let Some(mut entry_mut) = self.inner.get(key) {
                entry_mut.mark_clean_and_snapshot();
                self.inner.insert(key.clone(), entry_mut);
            }
        }
        self.inner.sync();
        self.clear_dirty_state_keys();
    }

    /// Rolls back all dirty cache entries to the clean status.
    /// `Add`ed entries will be explicitly evicted from the state cache.
    /// `Update`d or `Remove`d entries will be reverted back to the clean snapshot.
    pub(crate) fn rollback_dirty_cache(&self) {
        let dirty_keys = self.get_dirty_state_keys();
        dirty_keys.into_iter().for_each(|key| {
            if let Some(mut entry) = self.get_entry(&key) {
                match entry.status {
                    CacheEntryStatus::Dirty(StateMut::Add) => {
                        self.inner.invalidate(&key);
                    },
                    CacheEntryStatus::Dirty(StateMut::Update) | CacheEntryStatus::Dirty(StateMut::Remove) => {
                        entry.revert_to_clean();
                        self.insert_entry(key, entry);
                    },
                    CacheEntryStatus::Clean => {
                        panic!("STATE MISMATCH: Key from `dirty_keys` points to a `Clean` cache entry. Key={key}");
                    }
                }
            } else {
                panic!("STATE MISMATCH: Key from `dirty_keys` not found from the state cache. Key={key}");
            }
        });
        self.clear_dirty_state_keys();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_common::{Octets, STATE_KEY_SIZE};
    use mini_moka::sync::ConcurrentCacheExt;

    #[test]
    fn test_state_cache_eviction() {
        let capacity = 3;
        let cache = StateCache::new(capacity);
        assert_eq!(cache.inner.entry_count(), 0);
        // Add keys: [0, 0, ...], [1, 0, ...], [2, 0, ...]
        for i in 0..capacity {
            let mut key_arr = [0u8; STATE_KEY_SIZE];
            key_arr[0] = i as u8;
            let data = Octets::from_vec(vec![i as u8; 3]);
            cache.insert_entry(
                StateKey::new(key_arr),
                CacheEntry::new(StateEntryType::Raw(data)),
            );
        }
        cache.inner.sync();
        assert_eq!(cache.inner.entry_count() as usize, capacity);

        // New key: [3, 0, ...]
        let mut key_arr = [0u8; STATE_KEY_SIZE];
        key_arr[0] = capacity as u8;
        let data = Octets::from_vec(vec![capacity as u8; 3]);
        cache.insert_entry(
            StateKey::new(key_arr),
            CacheEntry::new(StateEntryType::Raw(data)),
        );
        cache.inner.sync();
        assert!(
            cache.inner.entry_count() as usize <= capacity,
            "Cache eviction must work and total entries should not exceed the max capacity"
        );
    }
}
