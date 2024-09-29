use crate::trie::utils::bytes_to_lsb_bits;
use dashmap::DashMap;
use rjam_common::{Hash32, Octets};
use rjam_db::rjam_db::StateDB;
use rjam_merkle_trie::{
    merkle_db::MerkleDB,
    types::{LeafType, MerkleError},
};
use rjam_types::state::{
    authorizer::{AuthPool, AuthQueue},
    disputes::DisputesState,
    entropy::EntropyAccumulator,
    histories::BlockHistories,
    privileged::PrivilegedServices,
    reports::PendingReports,
    safrole::SafroleState,
    services_wip::AccountMetadata,
    statistics::ValidatorStats,
    timeslot::Timeslot,
    validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("Merkle error: {0}")]
    MerkleError(#[from] MerkleError),
}

pub enum StateType {
    AuthPool(AuthPool),                       // alpha
    AuthQueue(AuthQueue),                     // phi
    BlockHistories(BlockHistories),           // beta
    SafroleState(SafroleState),               // gamma
    DisputesState(DisputesState),             // psi
    EntropyAccumulator(EntropyAccumulator),   // eta
    StagingValidatorSet(StagingValidatorSet), // iota
    ActiveValidatorSet(ActiveValidatorSet),   // kappa
    PastValidatorSet(PastValidatorSet),       // lambda
    PendingReports(PendingReports),           // rho
    Timeslot(Timeslot),                       // tau
    PrivilegedServices(PrivilegedServices),   // chi
    ValidatorStats(ValidatorStats),           // pi
    AccountMetadata(AccountMetadata),         // sigma (partial)
}

/// Index of each state component used for state-key (Merkle path) construction
#[repr(u8)]
pub(crate) enum StateKeyConstant {
    AuthPool = 1,            // alpha
    AuthQueue = 2,           // phi
    BlockHistories = 3,      // beta
    SafroleState = 4,        // gamma
    DisputesState = 5,       // psi
    EntropyAccumulator = 6,  // eta
    StagingValidatorSet = 7, // iota
    ActiveValidatorSet = 8,  // kappa
    PastValidatorSet = 9,    // lambda
    PendingReports = 10,     // rho
    Timeslot = 11,           // tau
    PrivilegedServices = 12, // chi
    ValidatorStats = 13,     // pi
    AccountMetadata = 255,   // sigma (partial)
}

impl From<StateKeyConstant> for u8 {
    fn from(state_key: StateKeyConstant) -> Self {
        state_key as u8
    }
}

pub(crate) fn construct_key<T: Into<u8>>(i: T) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i.into();
    key
}

pub(crate) fn construct_key_with_service<T: Into<u8>>(i: T, s: u32) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i.into();
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

pub(crate) fn construct_key_with_service_and_data(s: u32, h: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];

    let s_bytes = s.to_be_bytes();
    let h_len = h.len().min(28);

    for i in 0..4 {
        key[i * 2] = s_bytes[i];
        if i < h_len {
            key[i * 2 + 1] = h[i];
        }
    }

    if h_len > 4 {
        key[8..8 + h_len - 4].copy_from_slice(&h[4..h_len]);
    }

    key
}

pub(crate) fn construct_key_with_service_and_hash(s: u32, h: &Hash32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

#[derive(Clone)]
enum CacheEntryStatus {
    Clean,
    Dirty,
}

struct CacheEntry {
    value: StateType,
    status: CacheEntryStatus,
}

impl CacheEntry {
    fn is_dirty(&self) -> bool {
        matches!(self.status, CacheEntryStatus::Dirty)
    }

    fn mark_dirty(&mut self) {
        self.status = CacheEntryStatus::Dirty;
    }

    fn mark_clean(&mut self) {
        self.status = CacheEntryStatus::Clean;
    }
}

struct StateCache {
    cache: Arc<DashMap<Hash32, CacheEntry>>,
}

impl StateCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
        }
    }
}

pub struct StateManager {
    state_db: Arc<StateDB>,
    merkle_db: Arc<MerkleDB>,
    cache: Arc<StateCache>,
}

impl StateManager {
    pub fn new(state_db: Arc<StateDB>, merkle_db: Arc<MerkleDB>) -> Self {
        Self {
            state_db,
            merkle_db,
            cache: Arc::new(StateCache::new()),
        }
    }

    // fn retrieve_state_encoded(&self, state_key: &Hash32) -> Result<Octets, StateManagerError> {
    //     // Traverse the trie
    //     let (leaf_type, state_data) = self.merkle_db.retrieve(state_key)?;
    //
    //
    //
    //     let state_data = match leaf_type {
    //         LeafType::Embedded => state_data,
    //         LeafType::Regular => state_data,
    //     };
    //
    //
    //
    //     Ok(state_data)
    // }
    //
    // pub fn get_auth_pool_state(&self) -> Result<AuthPool, StateManagerError> {
    //     // Check the cache
    //     if let Some(entry) = self.cache.read()?.get(state_key) {
    //         return Ok(entry.clone());
    //     }
    // }

    pub fn get_auth_queue_state() {}

    pub fn get_block_histories_state() {}

    pub fn get_safrole_state() {}

    pub fn get_disputes_state() {}

    pub fn get_entropy_accumulator_state() {}

    pub fn get_staging_validator_set_state() {}

    pub fn get_active_validator_set_state() {}

    pub fn get_past_validator_set_state() {}

    pub fn get_pending_reports_state() {}

    pub fn get_timeslot_state() {}

    pub fn get_privileged_services_state() {}

    pub fn get_validator_stats_state() {}

    pub fn get_account_metadata() {}

    pub fn get_account_storage_entry() {}

    pub fn get_account_preimages_entry() {}

    pub fn get_account_lookups_entry() {}
}
