use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamDecode, JamEncodeFixed};
use rjam_common::{Address, Hash32, Octets};
use rjam_crypto::utils::octets_to_hash32;
use rjam_db::{StateDB, StateDBError};
use rjam_merkle_trie::{
    error::MerkleError,
    merkle_db::MerkleDB,
    types::{LeafType, EMPTY_HASH},
};
use rjam_types::state::{
    authorizer::{AuthPool, AuthQueue},
    disputes::DisputesState,
    entropy::EntropyAccumulator,
    histories::BlockHistories,
    privileged::PrivilegedServices,
    reports::PendingReports,
    safrole::SafroleState,
    services::{AccountLookupsEntry, AccountMetadata, AccountPreimagesEntry, AccountStorageEntry},
    statistics::ValidatorStats,
    timeslot::Timeslot,
    validators::{ActiveSet, PastSet, StagingSet},
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("State key not initialized")]
    StateKeyNotInitialized,
    #[error("Cache entry not found")]
    CacheEntryNotFound,
    #[error("Unexpected entry type")]
    UnexpectedEntryType,
    #[error("Merkle error: {0}")]
    MerkleError(#[from] MerkleError),
    #[error("StateDB error: {0}")]
    StateDBError(#[from] StateDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Clone)]
pub enum StateEntryType {
    AuthPool(AuthPool),                     // alpha
    AuthQueue(AuthQueue),                   // phi
    BlockHistories(BlockHistories),         // beta
    SafroleState(SafroleState),             // gamma
    DisputesState(DisputesState),           // psi
    EntropyAccumulator(EntropyAccumulator), // eta
    StagingSet(StagingSet),                 // iota
    ActiveSet(ActiveSet),                   // kappa
    PastSet(PastSet),                       // lambda
    PendingReports(PendingReports),         // rho
    Timeslot(Timeslot),                     // tau
    PrivilegedServices(PrivilegedServices), // chi
    ValidatorStats(ValidatorStats),         // pi
    AccountMetadata(AccountMetadata),       // sigma (partial)
    AccountStorageEntry(AccountStorageEntry),
    AccountLookupsEntry(AccountLookupsEntry),
    AccountPreimagesEntry(AccountPreimagesEntry),
}

/// Index of each state component used for state-key (Merkle path) construction
#[repr(u8)]
pub enum StateKeyConstant {
    AuthPool = 1,            // alpha
    AuthQueue = 2,           // phi
    BlockHistories = 3,      // beta
    SafroleState = 4,        // gamma
    DisputesState = 5,       // psi
    EntropyAccumulator = 6,  // eta
    StagingSet = 7,          // iota
    ActiveSet = 8,           // kappa
    PastSet = 9,             // lambda
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

pub(crate) fn construct_state_key<T: Into<u8>>(i: T) -> Hash32 {
    let mut key = EMPTY_HASH;
    key[0] = i.into();
    key
}

pub(crate) fn construct_account_metadata_state_key<T: Into<u8>>(i: T, s: Address) -> Hash32 {
    let mut key = EMPTY_HASH;
    key[0] = i.into();
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

pub(crate) fn construct_account_storage_state_key(s: Address, h: &Hash32) -> Hash32 {
    let mut key = EMPTY_HASH;
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

/// Applies logical NOT operation on a Hash32 type
fn not_hash_slice(h: &Hash32) -> [u8; 28] {
    let mut result = [0u8; 28];
    for (i, &byte) in h[4..].iter().enumerate() {
        result[i] = !byte;
    }
    result
}

pub(crate) fn construct_account_lookups_state_key(
    s: Address,
    h: &Hash32,
    l: u32,
) -> Result<Hash32, StateManagerError> {
    let mut lookups_key_encoded = vec![];
    l.encode_to_fixed(&mut lookups_key_encoded, 4)?;
    lookups_key_encoded.extend(not_hash_slice(h).to_vec());

    Ok(construct_account_storage_state_key(
        s,
        octets_to_hash32(&lookups_key_encoded).as_ref().unwrap(),
    ))
}

#[derive(Clone)]
pub enum StateWriteOp {
    Update,
    Add,
    Remove,
}

#[derive(Clone)]
enum CacheEntryStatus {
    Clean,
    Dirty(StateWriteOp),
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
        matches!(self.status, CacheEntryStatus::Dirty(_))
    }

    fn mark_dirty(&mut self, write_op: StateWriteOp) {
        self.status = CacheEntryStatus::Dirty(write_op);
    }

    fn mark_clean(&mut self) {
        self.status = CacheEntryStatus::Clean;
    }
}

pub struct StateManager {
    state_db: Option<Arc<StateDB>>,
    merkle_db: Option<Arc<MerkleDB>>,
    cache: Arc<DashMap<Hash32, CacheEntry>>,
}

impl StateManager {
    pub fn new_for_test() -> Self {
        Self {
            state_db: None,
            merkle_db: None,
            cache: Arc::new(DashMap::new()),
        }
    }

    pub fn load_state_for_test(
        &mut self,
        state_key_constant: StateKeyConstant,
        state_entry_type: StateEntryType,
    ) {
        let state_key = construct_state_key(state_key_constant);
        self.cache
            .insert(state_key, CacheEntry::new(state_entry_type));
    }

    pub fn new(state_db: Arc<StateDB>, merkle_db: Arc<MerkleDB>) -> Self {
        Self {
            state_db: Some(state_db),
            merkle_db: Some(merkle_db),
            cache: Arc::new(DashMap::new()),
        }
    }

    pub fn account_exists(&self, address: Address) -> Result<bool, StateManagerError> {
        match self.get_account_metadata(address)? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    pub fn check(&self, address: Address) -> Result<Address, StateManagerError> {
        let mut check_address = address;
        loop {
            if !self.account_exists(check_address)? {
                return Ok(check_address);
            }

            check_address = ((check_address as u64 - (1 << 8) + 1) % ((1 << 32) - (1 << 9))
                + (1 << 8)) as Address;
        }
    }

    /// This function assumes that the code preimage is available.
    /// For on-chain PVM invocations (`Accumulate` and `On-Transfer`) get account code directly from this function
    /// whereas for off-chain/in-core PVM invocations (`Refine` and `Is-Authorized`) conduct historical lookups.
    pub fn get_account_code(&self, address: Address) -> Result<Option<Octets>, StateManagerError> {
        let code_hash = match self.get_account_metadata(address)? {
            Some(metadata) => metadata.account_info.code_hash,
            None => return Ok(None),
        };

        match self.get_account_preimages_entry(address, &code_hash)? {
            Some(entry) => Ok(Some(entry.value)),
            None => Ok(None),
        }
    }

    /// The historical lookup function
    pub fn lookup_preimage(
        &self,
        address: Address,
        reference_timeslot: &Timeslot,
        preimage_hash: &Hash32,
    ) -> Result<Option<Octets>, StateManagerError> {
        let preimage = match self.get_account_preimages_entry(address, preimage_hash)? {
            Some(preimage) => preimage.value,
            None => return Ok(None),
        };
        let preimage_length = preimage.len() as u32;
        let lookup_timeslots =
            match self.get_account_lookups_entry(address, (preimage_hash, preimage_length))? {
                Some(lookup_timeslots) => lookup_timeslots.value,
                None => return Ok(None),
            };

        let valid = match lookup_timeslots.as_slice() {
            [] => false,
            [first] => first <= reference_timeslot,
            [first, second] => first <= reference_timeslot && reference_timeslot < second,
            [first, second, third] => {
                (first <= reference_timeslot && reference_timeslot < second)
                    || third <= reference_timeslot
            }
            _ => false,
        };

        if valid {
            Ok(Some(preimage))
        } else {
            Ok(None)
        }
    }

    fn retrieve_state_encoded(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<Octets>, StateManagerError> {
        if let Some(merkle_db) = &self.merkle_db {
            let (leaf_type, state_data) = match merkle_db.retrieve(state_key)? {
                Some((leaf_type, state_data)) => (leaf_type, state_data),
                None => return Ok(None),
            };

            if let Some(state_db) = &self.state_db {
                let state_data = match leaf_type {
                    LeafType::Embedded => state_data,
                    LeafType::Regular => state_db.get_entry(&state_data)?.unwrap(),
                };
                return Ok(Some(state_data));
            }
        }
        Ok(None)
    }

    //
    // Immutable/mutable references to state components and account storage entries
    //

    pub fn get_auth_pool(&self) -> Result<AuthPool, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::AuthPool);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AuthPool(auth_pool) = entry_ref.value.clone() {
                return Ok(auth_pool);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let auth_pool = AuthPool::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AuthPool(auth_pool.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(auth_pool)
    }

    pub fn with_mut_auth_pool<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AuthPool),
    {
        let state_key = construct_state_key(StateKeyConstant::AuthPool);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AuthPool(ref mut auth_pool) = cache_entry.value {
            f(auth_pool); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_auth_queue(&self) -> Result<AuthQueue, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::AuthQueue);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AuthQueue(auth_queue) = entry_ref.value.clone() {
                return Ok(auth_queue);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let auth_queue = AuthQueue::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AuthQueue(auth_queue.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(auth_queue)
    }

    pub fn with_mut_auth_queue<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AuthQueue),
    {
        let state_key = construct_state_key(StateKeyConstant::AuthQueue);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AuthQueue(ref mut auth_queue) = cache_entry.value {
            f(auth_queue); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_block_histories(&self) -> Result<BlockHistories, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::BlockHistories);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::BlockHistories(block_histories) = entry_ref.value.clone() {
                return Ok(block_histories);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let block_histories = BlockHistories::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::BlockHistories(block_histories.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(block_histories)
    }

    pub fn with_mut_block_histories<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut BlockHistories),
    {
        let state_key = construct_state_key(StateKeyConstant::BlockHistories);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::BlockHistories(ref mut block_histories) = cache_entry.value {
            f(block_histories); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_safrole(&self) -> Result<SafroleState, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::SafroleState);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::SafroleState(safrole) = entry_ref.value.clone() {
                return Ok(safrole);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let safrole = SafroleState::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::SafroleState(safrole.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(safrole)
    }

    pub fn with_mut_safrole<F>(&self, write_op: StateWriteOp, f: F) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut SafroleState),
    {
        let state_key = construct_state_key(StateKeyConstant::SafroleState);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::SafroleState(ref mut safrole) = cache_entry.value {
            f(safrole); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_disputes(&self) -> Result<DisputesState, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::DisputesState);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::DisputesState(dispute_state) = entry_ref.value.clone() {
                return Ok(dispute_state);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let dispute_state = DisputesState::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::DisputesState(dispute_state.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(dispute_state)
    }

    pub fn with_mut_disputes<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut DisputesState),
    {
        let state_key = construct_state_key(StateKeyConstant::DisputesState);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::DisputesState(ref mut disputes) = cache_entry.value {
            f(disputes); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_entropy_accumulator(&self) -> Result<EntropyAccumulator, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::EntropyAccumulator);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::EntropyAccumulator(entropy_acc) = entry_ref.value.clone() {
                return Ok(entropy_acc);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let entropy_acc = EntropyAccumulator::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::EntropyAccumulator(entropy_acc.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(entropy_acc)
    }

    pub fn with_mut_entropy_accumulator<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut EntropyAccumulator),
    {
        let state_key = construct_state_key(StateKeyConstant::EntropyAccumulator);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::EntropyAccumulator(ref mut entropy_accumulator) = cache_entry.value {
            f(entropy_accumulator); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_staging_set(&self) -> Result<StagingSet, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::StagingSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::StagingSet(staging_set) = entry_ref.value.clone() {
                return Ok(staging_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let staging_set = StagingSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::StagingSet(staging_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(staging_set)
    }

    pub fn with_mut_staging_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut StagingSet),
    {
        let state_key = construct_state_key(StateKeyConstant::StagingSet);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::StagingSet(ref mut staging_set) = cache_entry.value {
            f(staging_set); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_active_set(&self) -> Result<ActiveSet, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::ActiveSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::ActiveSet(active_set) = entry_ref.value.clone() {
                return Ok(active_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let active_set = ActiveSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::ActiveSet(active_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(active_set)
    }

    pub fn with_mut_active_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut ActiveSet),
    {
        let state_key = construct_state_key(StateKeyConstant::ActiveSet);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::ActiveSet(ref mut active_set) = cache_entry.value {
            f(active_set); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_past_set(&self) -> Result<PastSet, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::PastSet);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PastSet(past_set) = entry_ref.value.clone() {
                return Ok(past_set);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let past_set = PastSet::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PastSet(past_set.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(past_set)
    }

    pub fn with_mut_past_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PastSet),
    {
        let state_key = construct_state_key(StateKeyConstant::PastSet);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::PastSet(ref mut past_set) = cache_entry.value {
            f(past_set); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_pending_reports(&self) -> Result<PendingReports, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::PendingReports);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PendingReports(pending_reports) = entry_ref.value.clone() {
                return Ok(pending_reports);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let pending_reports = PendingReports::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PendingReports(pending_reports.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(pending_reports)
    }

    pub fn with_mut_pending_reports<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PendingReports),
    {
        let state_key = construct_state_key(StateKeyConstant::PendingReports);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::PendingReports(ref mut pending_reports) = cache_entry.value {
            f(pending_reports); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_timeslot(&self) -> Result<Timeslot, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::Timeslot);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::Timeslot(timeslot) = entry_ref.value.clone() {
                return Ok(timeslot);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let timeslot = Timeslot::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::Timeslot(timeslot.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(timeslot)
    }

    pub fn with_mut_timeslot<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut Timeslot),
    {
        let state_key = construct_state_key(StateKeyConstant::Timeslot);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::Timeslot(ref mut timeslot) = cache_entry.value {
            f(timeslot); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_privileged_services(&self) -> Result<PrivilegedServices, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::PrivilegedServices);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::PrivilegedServices(privileged_services) = entry_ref.value.clone()
            {
                return Ok(privileged_services);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let privileged_services = PrivilegedServices::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::PrivilegedServices(
            privileged_services.clone(),
        ));
        self.cache.insert(state_key, cache_entry);

        Ok(privileged_services)
    }

    pub fn with_mut_privileged_services<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PrivilegedServices),
    {
        let state_key = construct_state_key(StateKeyConstant::PrivilegedServices);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::PrivilegedServices(ref mut privileged_services) = cache_entry.value {
            f(privileged_services); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_validator_stats(&self) -> Result<ValidatorStats, StateManagerError> {
        let state_key = construct_state_key(StateKeyConstant::ValidatorStats);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::ValidatorStats(validator_stats) = entry_ref.value.clone() {
                return Ok(validator_stats);
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let validator_stats = ValidatorStats::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::ValidatorStats(validator_stats.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(validator_stats)
    }

    pub fn with_mut_validator_stats<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut ValidatorStats),
    {
        let state_key = construct_state_key(StateKeyConstant::ValidatorStats);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::ValidatorStats(ref mut validator_stats) = cache_entry.value {
            f(validator_stats); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_account_metadata(
        &self,
        address: Address,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        let state_key =
            construct_account_metadata_state_key(StateKeyConstant::AccountMetadata, address);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountMetadata(account_metadata) = entry_ref.value.clone() {
                return Ok(Some(account_metadata));
            }
        }

        // Retrieve the state from the DB
        let state_data = match self.retrieve_state_encoded(&state_key)? {
            Some(state_data) => state_data,
            None => return Ok(None),
        };
        let account_metadata = AccountMetadata::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountMetadata(account_metadata.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(Some(account_metadata))
    }

    pub fn with_mut_account_metadata<F>(
        &self,
        write_op: StateWriteOp,
        address: Address,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountMetadata),
    {
        let state_key =
            construct_account_metadata_state_key(StateKeyConstant::AccountMetadata, address);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AccountMetadata(ref mut account_metadata) = cache_entry.value {
            f(account_metadata); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_account_storage_entry(
        &self,
        address: Address,
        storage_key: &Hash32,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        let state_key = construct_account_storage_state_key(address, storage_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountStorageEntry(storage_entry) = entry_ref.value.clone() {
                return Ok(Some(storage_entry));
            }
        }

        // Retrieve the state from the DB
        let storage_entry = AccountStorageEntry {
            // key: storage_key.clone(),
            value: match self.retrieve_state_encoded(&state_key)? {
                Some(state_data) => state_data,
                None => return Ok(None),
            },
        };

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountStorageEntry(storage_entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(Some(storage_entry))
    }

    pub fn with_mut_account_storage_entry<F>(
        &self,
        write_op: StateWriteOp,
        address: Address,
        storage_key: &Hash32,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountStorageEntry),
    {
        let state_key = construct_account_storage_state_key(address, storage_key);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AccountStorageEntry(ref mut account_storage_entry) =
            cache_entry.value
        {
            f(account_storage_entry); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_account_preimages_entry(
        &self,
        address: Address,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        let state_key = construct_account_storage_state_key(address, preimages_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountPreimagesEntry(preimages_entry) = entry_ref.value.clone()
            {
                return Ok(Some(preimages_entry));
            }
        }

        // Retrieve the state from the DB
        let preimages_entry = AccountPreimagesEntry {
            // key: preimages_key.clone(),
            value: match self.retrieve_state_encoded(&state_key)? {
                Some(state_data) => state_data,
                None => return Ok(None),
            },
        };

        // Insert into the cache
        let cache_entry = CacheEntry::new(StateEntryType::AccountPreimagesEntry(
            preimages_entry.clone(),
        ));
        self.cache.insert(state_key, cache_entry);

        Ok(Some(preimages_entry))
    }

    pub fn with_mut_account_preimages_entry<F>(
        &self,
        write_op: StateWriteOp,
        address: Address,
        preimages_key: &Hash32,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountPreimagesEntry),
    {
        let state_key = construct_account_storage_state_key(address, preimages_key);

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AccountPreimagesEntry(ref mut account_preimages_entry) =
            cache_entry.value
        {
            f(account_preimages_entry); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    pub fn get_account_lookups_entry(
        &self,
        address: Address,
        lookups_key: (&Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let (h, l) = lookups_key;
        let state_key = construct_account_lookups_state_key(address, h, l)?;

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountLookupsEntry(lookups_entry) = entry_ref.value.clone() {
                return Ok(Some(lookups_entry));
            }
        }

        // Retrieve the state from the DB
        let state_data = match self.retrieve_state_encoded(&state_key)? {
            Some(state_data) => state_data,
            None => return Ok(None),
        };
        let lookups_entry = AccountLookupsEntry::decode(&mut state_data.as_slice())?;

        // Insert into the cache
        let cache_entry =
            CacheEntry::new(StateEntryType::AccountLookupsEntry(lookups_entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(Some(lookups_entry))
    }

    pub fn with_mut_account_lookups_entry<F>(
        &self,
        write_op: StateWriteOp,
        address: Address,
        lookups_key: (&Hash32, u32),
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountLookupsEntry),
    {
        let (h, l) = lookups_key;
        let state_key = construct_account_lookups_state_key(address, h, l)?;

        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let StateEntryType::AccountLookupsEntry(ref mut account_lookups_entry) =
            cache_entry.value
        {
            f(account_lookups_entry); // call the closure to mutate the state
            cache_entry.mark_dirty(write_op);

            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }
}
