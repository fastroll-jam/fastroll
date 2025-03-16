use crate::{error::StateManagerError, state_utils::StateEntryType};
use dashmap::DashMap;
use rjam_codec::JamEncode;
use rjam_common::Hash32;
use rjam_state_merkle::types::MerkleWriteOp;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq)]
pub enum StateMut {
    Add,
    Update,
    Remove,
}

#[derive(Debug, Clone)]
pub enum CacheEntryStatus {
    Clean,
    Dirty(StateMut),
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached snapshot of clean state entry, synchronized with the DB.
    pub(crate) clean_snapshot: StateEntryType,
    /// Latest state cache entry value.
    pub value: StateEntryType,
    /// State cache status (Clean or Dirty).
    pub status: CacheEntryStatus,
}

impl CacheEntry {
    pub fn new(value: StateEntryType) -> Self {
        Self {
            clean_snapshot: value.clone(),
            value,
            status: CacheEntryStatus::Clean,
        }
    }

    pub(crate) fn is_dirty(&self) -> bool {
        matches!(self.status, CacheEntryStatus::Dirty(_))
    }

    pub(crate) fn mark_dirty(&mut self, state_mut: StateMut) {
        self.status = CacheEntryStatus::Dirty(state_mut);
    }

    pub(crate) fn mark_clean_and_snapshot(&mut self) {
        self.status = CacheEntryStatus::Clean;
        self.clean_snapshot = self.value.clone(); // snapshot clean value
    }

    pub fn as_merkle_state_mut(
        &self,
        state_key: &Hash32,
    ) -> Result<MerkleWriteOp, StateManagerError> {
        let op = if let CacheEntryStatus::Dirty(op) = &self.status {
            op
        } else {
            return Err(StateManagerError::NotDirtyCache);
        };

        let encoded = self.value.encode()?;
        let merkle_state_mut = match op {
            StateMut::Add => MerkleWriteOp::Add(*state_key, encoded),
            StateMut::Update => MerkleWriteOp::Update(*state_key, encoded),
            StateMut::Remove => MerkleWriteOp::Remove(*state_key),
        };

        Ok(merkle_state_mut)
    }
}

pub struct StateCache {
    inner: DashMap<Hash32, CacheEntry>, // (state_key, cache_entry)
}

impl Deref for StateCache {
    type Target = DashMap<Hash32, CacheEntry>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StateCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Default for StateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StateCache {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    pub(crate) fn collect_dirty(&self) -> Vec<(Hash32, CacheEntry)> {
        self.inner
            .iter()
            .filter_map(|entry_ref| match entry_ref.value().status {
                CacheEntryStatus::Clean => None,
                CacheEntryStatus::Dirty(_) => Some((*entry_ref.key(), entry_ref.value().clone())),
            })
            .collect()
    }

    pub(crate) fn mark_entries_clean(&self, dirty_entries: &[(Hash32, CacheEntry)]) {
        for (key, _) in dirty_entries.iter() {
            if let Some(mut entry_mut) = self.inner.get_mut(key) {
                entry_mut.value_mut().mark_clean_and_snapshot();
            }
        }
    }
}
