use crate::trie::utils::bytes_to_lsb_bits;
use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamDecode};
use rjam_common::{Address, Hash32, Octets};
use rjam_crypto::utils::octets_to_hash32;
use rjam_db::rjam_db::{StateDB, StateDBError};
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
    services_wip::{
        AccountLookupsEntry, AccountMetadata, AccountPreimagesEntry, AccountStorageEntry,
    },
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
    #[error("StateDB error: {0}")]
    StateDBError(#[from] StateDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Clone)]
pub enum StateEntryType {
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
    AccountStorageEntry(AccountStorageEntry),
    AccountLookupsEntry(AccountLookupsEntry),
    AccountPreimagesEntry(AccountPreimagesEntry),
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

pub(crate) fn construct_key_with_service<T: Into<u8>>(i: T, s: Address) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i.into();
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

pub(crate) fn construct_key_with_service_and_hash(s: Address, h: &Hash32) -> Hash32 {
    let mut key = [0u8; 32];
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

// TODO: review
pub(crate) fn construct_key_with_service_and_data(s: Address, h: &Hash32) -> Hash32 {
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

#[derive(Clone)]
enum CacheEntryStatus {
    Clean,
    Dirty,
}

struct CacheEntry {
    value: StateEntryType,
    status: CacheEntryStatus,
}

impl CacheEntry {
    fn new(value: StateEntryType) -> Self {
        Self {
            value,
            status: CacheEntryStatus::Clean,
        }
    }

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

pub struct StateManager {
    state_db: Arc<StateDB>,
    merkle_db: Arc<MerkleDB>,
    cache: Arc<DashMap<Hash32, CacheEntry>>,
}

impl StateManager {
    pub fn new(state_db: Arc<StateDB>, merkle_db: Arc<MerkleDB>) -> Self {
        Self {
            state_db,
            merkle_db,
            cache: Arc::new(DashMap::new()),
        }
    }

    fn retrieve_state_encoded(&self, state_key: &Hash32) -> Result<Octets, StateManagerError> {
        // Traverse the trie
        let (leaf_type, state_data) = self.merkle_db.retrieve(state_key)?;

        let state_data = match leaf_type {
            LeafType::Embedded => state_data,
            LeafType::Regular => {
                // state_data is hash of state data
                self.state_db.get_entry(&state_data)?.unwrap()
            }
        };

        Ok(state_data)
    }

    pub fn get_auth_pool_state(&self) -> Result<AuthPool, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::AuthPool);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AuthPool(auth_pool) = entry_ref.value.clone() {
                return Ok(auth_pool);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let auth_pool = AuthPool::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AuthPool(auth_pool.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(auth_pool)
    }

    pub fn get_auth_queue_state(&self) -> Result<AuthQueue, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::AuthQueue);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AuthQueue(auth_queue) = entry_ref.value.clone() {
                return Ok(auth_queue);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let auth_queue = AuthQueue::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AuthQueue(auth_queue.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(auth_queue)
    }

    pub fn get_block_histories_state(&self) -> Result<BlockHistories, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::BlockHistories);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::BlockHistories(block_histories) = entry_ref.value.clone() {
                return Ok(block_histories);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let block_histories = BlockHistories::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::BlockHistories(block_histories.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(block_histories)
    }

    pub fn get_safrole_state(&self) -> Result<SafroleState, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::SafroleState);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::SafroleState(safrole) = entry_ref.value.clone() {
                return Ok(safrole);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let safrole = SafroleState::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::SafroleState(safrole.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(safrole)
    }

    pub fn get_disputes_state(&self) -> Result<DisputesState, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::DisputesState);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::DisputesState(dispute_state) = entry_ref.value.clone() {
                return Ok(dispute_state);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let dispute_state = DisputesState::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::DisputesState(dispute_state.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(dispute_state)
    }

    pub fn get_entropy_accumulator_state(&self) -> Result<EntropyAccumulator, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::EntropyAccumulator);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::EntropyAccumulator(entropy_acc) = entry_ref.value.clone() {
                return Ok(entropy_acc);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let entropy_acc = EntropyAccumulator::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::EntropyAccumulator(entropy_acc.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(entropy_acc)
    }

    pub fn get_staging_validator_set_state(
        &self,
    ) -> Result<StagingValidatorSet, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::StagingValidatorSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::StagingValidatorSet(staging_set) = entry_ref.value.clone() {
                return Ok(staging_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let staging_set = StagingValidatorSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::StagingValidatorSet(staging_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(staging_set)
    }

    pub fn get_active_validator_set_state(&self) -> Result<ActiveValidatorSet, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::ActiveValidatorSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::ActiveValidatorSet(active_set) = entry_ref.value.clone() {
                return Ok(active_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let active_set = ActiveValidatorSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::ActiveValidatorSet(active_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(active_set)
    }

    pub fn get_past_validator_set_state(&self) -> Result<PastValidatorSet, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::PastValidatorSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PastValidatorSet(past_set) = entry_ref.value.clone() {
                return Ok(past_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let past_set = PastValidatorSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PastValidatorSet(past_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(past_set)
    }

    pub fn get_pending_reports_state(&self) -> Result<PendingReports, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::PendingReports);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PendingReports(pending_reports) = entry_ref.value.clone() {
                return Ok(pending_reports);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let pending_reports = PendingReports::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PendingReports(pending_reports.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(pending_reports)
    }

    pub fn get_timeslot_state(&self) -> Result<Timeslot, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::Timeslot);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::Timeslot(timeslot) = entry_ref.value.clone() {
                return Ok(timeslot);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let timeslot = Timeslot::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::Timeslot(timeslot.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(timeslot)
    }

    pub fn get_privileged_services_state(&self) -> Result<PrivilegedServices, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::PrivilegedServices);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PrivilegedServices(privileged_services) = entry_ref.value.clone()
            {
                return Ok(privileged_services);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let privileged_services = PrivilegedServices::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PrivilegedServices(
            privileged_services.clone(),
        ));
        self.cache.insert(state_key, cache_entry);

        Ok(privileged_services)
    }

    pub fn get_validator_stats_state(&self) -> Result<ValidatorStats, StateManagerError> {
        let state_key = construct_key(StateKeyConstant::ValidatorStats);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::ValidatorStats(validator_stats) = entry_ref.value.clone() {
                return Ok(validator_stats);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let validator_stats = ValidatorStats::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::ValidatorStats(validator_stats.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(validator_stats)
    }

    pub fn get_account_metadata(
        &self,
        address: Address,
    ) -> Result<AccountMetadata, StateManagerError> {
        let state_key = construct_key_with_service(StateKeyConstant::AccountMetadata, address);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountMetadata(account_metadata) = entry_ref.value.clone() {
                return Ok(account_metadata);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let account_metadata = AccountMetadata::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountMetadata(account_metadata.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(account_metadata)
    }

    pub fn get_account_storage_entry(
        &self,
        address: Address,
        storage_key: &Hash32,
    ) -> Result<AccountStorageEntry, StateManagerError> {
        let state_key = construct_key_with_service_and_hash(address, storage_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountStorageEntry(storage_entry) = entry_ref.value.clone() {
                return Ok(storage_entry);
            }
        }

        // Retrieve the state from the DB
        let storage_entry = AccountStorageEntry {
            // key: storage_key.clone(),
            value: self.retrieve_state_encoded(&state_key)?,
        };

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountStorageEntry(storage_entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(storage_entry)
    }

    pub fn get_account_preimages_entry(
        &self,
        address: Address,
        preimages_key: &Hash32,
    ) -> Result<AccountPreimagesEntry, StateManagerError> {
        let state_key = construct_key_with_service_and_hash(address, preimages_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountPreimagesEntry(preimages_entry) = entry_ref.value.clone()
            {
                return Ok(preimages_entry);
            }
        }

        // Retrieve the state from the DB
        let preimages_entry = AccountPreimagesEntry {
            // key: preimages_key.clone(),
            value: self.retrieve_state_encoded(&state_key)?,
        };

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AccountPreimagesEntry(
            preimages_entry.clone(),
        ));
        self.cache.insert(state_key, cache_entry);

        Ok(preimages_entry)
    }

    pub fn get_account_lookups_entry(
        &self,
        address: Address,
        lookups_key: &Hash32,
    ) -> Result<AccountLookupsEntry, StateManagerError> {
        // FIXME: with exact encoding rule for the `h`: utilize preimage length
        let state_key = construct_key_with_service_and_data(address, lookups_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountLookupsEntry(lookups_entry) = entry_ref.value.clone() {
                return Ok(lookups_entry);
            }
        }

        // Retrieve the state from the DB
        let state_data = self.retrieve_state_encoded(&state_key)?;
        let lookups_entry = AccountLookupsEntry::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountLookupsEntry(lookups_entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(lookups_entry)
    }
}
