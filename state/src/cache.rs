use crate::{
    error::StateManagerError,
    state_utils::{StateComponent, StateEntryType},
};
use fr_codec::prelude::*;
use fr_common::StateKey;
use fr_state_merkle::merkle_db::MerkleWriteOp;
use mini_moka::sync::Cache;

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

#[derive(Debug, Clone)]
pub(crate) struct CacheEntry {
    /// Cached snapshot of clean state entry, synchronized with the DB.
    pub(crate) clean_snapshot: StateEntryType,
    /// Latest state cache entry value.
    pub(crate) value: StateEntryType,
    /// State cache status (Clean or Dirty).
    pub(crate) status: CacheEntryStatus,
}

impl CacheEntry {
    pub fn new(value: StateEntryType) -> Self {
        Self {
            clean_snapshot: value.clone(),
            value,
            status: CacheEntryStatus::Clean,
        }
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

    pub fn mark_clean_and_snapshot(&mut self) {
        self.status = CacheEntryStatus::Clean;
        self.clean_snapshot = self.value.clone(); // snapshot clean value
    }
}

/// A thread-safe mapping from state keys to their corresponding cache entries.
pub struct StateCache {
    inner: Cache<StateKey, CacheEntry>,
}

impl StateCache {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            inner: Cache::new(max_capacity as u64),
        }
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
        self.inner.insert(key, entry)
    }

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

        let entry_mut = T::from_entry_type_mut(&mut cache_entry.value)
            .ok_or(StateManagerError::UnexpectedEntryType)?;
        f(entry_mut)?; // Call the closure to apply the state mutation

        // If cache entry is dirty with `StateMut::Add` and the new `state_mut` is `StateMut::Update`,
        // keep the entry marked with `StateMut::Add`. This allows mutating new entries before
        // they get committed to the db.
        if cache_entry.status != CacheEntryStatus::Dirty(StateMut::Add)
            || state_mut != StateMut::Update
        {
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
        self.inner.insert(key.clone(), cache_entry);
        Ok(())
    }

    pub(crate) fn collect_dirty(&self) -> Vec<(StateKey, CacheEntry)> {
        self.inner
            .iter()
            .filter_map(|entry_ref| match entry_ref.value().status {
                CacheEntryStatus::Clean => None,
                CacheEntryStatus::Dirty(_) => {
                    Some((entry_ref.key().clone(), entry_ref.value().clone()))
                }
            })
            .collect()
    }

    // Syncs up the state cache with the global state, by removing cache entries that are deleted
    // from the global state and marking added or updated entries as clean.
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
