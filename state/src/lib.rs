pub mod test_utils;

use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamEncode};
use rjam_common::{Address, Hash32, HASH32_EMPTY};
use rjam_crypto::CryptoError;
use rjam_db::KeyValueDBError;
use rjam_state_merkle::{
    error::StateMerkleError,
    merkle_db::MerkleDB,
    state_db::StateDB,
    types::{LeafType, MerkleWriteOp},
    write_set::{AffectedNodesByDepth, MerkleWriteSet, StateDBWriteSet},
};
use rjam_types::{
    state::*,
    state_utils::{
        get_account_lookups_state_key, get_account_metadata_state_key,
        get_account_preimage_state_key, get_account_storage_state_key, get_simple_state_key,
        AccountStateComponent, SimpleStateComponent, StateComponent, StateEntryType,
        StateKeyConstant,
    },
};
use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("State key not initialized")]
    StateKeyNotInitialized,
    #[error("Cache entry not found")]
    CacheEntryNotFound,
    #[error("Cache entry is clean")]
    NotDirtyCache,
    #[error("Unexpected entry type")]
    UnexpectedEntryType,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Account storage dictionary entry not found")]
    StorageEntryNotFound,
    #[error("Account lookups dictionary entry not found")]
    LookupsEntryNotFound,
    #[error("Wrong StateMut operation type")]
    WrongStateMutType,
    #[error("State Entry with the state key already exists")]
    StateEntryAlreadyExists,
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Merkle error: {0}")]
    StateMerkleError(#[from] StateMerkleError),
    #[error("KeyValueDB error: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Debug, Clone)]
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

#[derive(Clone)]
struct CacheEntry {
    pub value: StateEntryType,
    pub status: CacheEntryStatus,
}

impl CacheEntry {
    fn new(value: StateEntryType) -> Self {
        Self {
            value,
            status: CacheEntryStatus::Clean,
        }
    }

    #[allow(dead_code)]
    fn is_dirty(&self) -> bool {
        matches!(self.status, CacheEntryStatus::Dirty(_))
    }

    fn mark_dirty(&mut self, state_mut: StateMut) {
        self.status = CacheEntryStatus::Dirty(state_mut);
    }

    fn mark_clean(&mut self) {
        self.status = CacheEntryStatus::Clean;
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

struct StateCache {
    inner: Arc<DashMap<Hash32, CacheEntry>>, // (state_key, cache_entry)
}

impl Deref for StateCache {
    type Target = Arc<DashMap<Hash32, CacheEntry>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for StateCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl StateCache {
    fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    fn collect_dirty(&self) -> Vec<(Hash32, CacheEntry)> {
        self.inner
            .iter()
            .filter_map(|entry_ref| match entry_ref.value().status {
                CacheEntryStatus::Clean => None,
                CacheEntryStatus::Dirty(_) => Some((*entry_ref.key(), entry_ref.value().clone())),
            })
            .collect()
    }

    fn mark_entries_clean(&self, dirty_entries: &[(Hash32, CacheEntry)]) {
        for (key, _) in dirty_entries.iter() {
            if let Some(mut entry_mut) = self.inner.get_mut(key) {
                entry_mut.value_mut().mark_clean();
            }
        }
    }
}

pub struct StateManager {
    state_db: Arc<RwLock<StateDB>>,
    merkle_db: Arc<RwLock<MerkleDB>>,
    cache: StateCache,
}

macro_rules! impl_simple_state_accessors {
    ($state_type:ty, $fn_type:ident) => {
        paste::paste! {
            pub fn [<get_ $fn_type>](&self) -> Result<$state_type, StateManagerError> {
                self.get_simple_state_entry()
            }

            pub fn [<with_mut_ $fn_type>]<F>(
                &self,
                state_mut: StateMut,
                f: F,
            ) -> Result<(), StateManagerError>
            where
                F: FnOnce(&mut $state_type),
            {
                self.with_mut_simple_state_entry(state_mut, f)
            }

            pub fn [<add_ $fn_type>](&self, state_entry: $state_type) -> Result<(), StateManagerError> {
                self.add_simple_state_entry(state_entry)
            }
        }
    };
}

impl StateManager {
    pub fn load_state_for_test(
        &mut self,
        state_key_constant: StateKeyConstant,
        state_entry_type: StateEntryType,
    ) {
        let state_key = get_simple_state_key(state_key_constant);
        self.cache
            .insert(state_key, CacheEntry::new(state_entry_type));
    }

    pub fn load_account_metadata_for_test(
        &mut self,
        address: Address,
        state_entry_type: StateEntryType,
    ) {
        let state_key = get_account_metadata_state_key(address);
        self.cache
            .insert(state_key, CacheEntry::new(state_entry_type));
    }

    pub fn merkle_root(&self) -> Hash32 {
        self.merkle_db_read().root()
    }

    pub fn new(state_db: StateDB, merkle_db: MerkleDB) -> Self {
        Self {
            state_db: Arc::new(RwLock::new(state_db)),
            merkle_db: Arc::new(RwLock::new(merkle_db)),
            cache: StateCache::new(),
        }
    }

    fn merkle_db_read(&self) -> RwLockReadGuard<'_, MerkleDB> {
        self.merkle_db.read().expect("RwLock poisoned")
    }

    fn merkle_db_write(&self) -> RwLockWriteGuard<'_, MerkleDB> {
        self.merkle_db.write().expect("RwLock poisoned")
    }

    fn state_db_read(&self) -> RwLockReadGuard<'_, StateDB> {
        self.state_db.read().expect("RwLock poisoned")
    }

    #[allow(dead_code)]
    fn state_db_write(&self) -> RwLockWriteGuard<'_, StateDB> {
        self.state_db.write().expect("RwLock poisoned")
    }

    pub fn account_exists(&self, address: Address) -> Result<bool, StateManagerError> {
        Ok(self.get_account_metadata(address)?.is_some())
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
    pub fn get_account_code(&self, address: Address) -> Result<Option<Vec<u8>>, StateManagerError> {
        let code_hash = match self.get_account_metadata(address)? {
            Some(metadata) => metadata.account_info.code_hash,
            None => return Ok(None),
        };

        match self.get_account_preimages_entry(address, &code_hash)? {
            Some(entry) => Ok(Some(entry.value.into_vec())),
            None => Ok(None),
        }
    }

    pub fn get_account_code_hash(
        &self,
        address: Address,
    ) -> Result<Option<Hash32>, StateManagerError> {
        match self.get_account_metadata(address)? {
            Some(metadata) => Ok(Some(metadata.account_info.code_hash)),
            None => Ok(None),
        }
    }

    /// The historical lookup function
    pub fn lookup_preimage(
        &self,
        address: Address,
        reference_timeslot: &Timeslot,
        preimage_hash: &Hash32,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        let preimage = match self.get_account_preimages_entry(address, preimage_hash)? {
            Some(preimage) => preimage.value,
            None => return Ok(None),
        };
        let preimage_length = preimage.len() as u32;
        let lookup_timeslots =
            match self.get_account_lookups_entry(address, &(*preimage_hash, preimage_length))? {
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
            Ok(Some(preimage.into_vec()))
        } else {
            Ok(None)
        }
    }

    // TODO: mark as private
    pub fn retrieve_state_encoded(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        let retrieved = match self.merkle_db_read().retrieve(state_key) {
            Ok(val) => val,
            Err(_) => return Ok(None),
        };

        let Some((leaf_type, state_data_hash)) = retrieved else {
            return Ok(None);
        };

        let state_data = match leaf_type {
            LeafType::Embedded => state_data_hash.to_vec(),
            LeafType::Regular => {
                // The state data hash is used as the key in the StateDB
                let Some(entry) = self.state_db_read().get_entry(&state_data_hash)? else {
                    return Ok(None);
                };
                entry
            }
        };

        Ok(Some(state_data))
    }

    /// Commits a single dirty cache entry into `MerkleDB` and `StateDB`.
    pub fn commit_single_dirty_cache(&self, state_key: &Hash32) -> Result<(), StateManagerError> {
        let mut cache_entry = self
            .cache
            .get_mut(state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let CacheEntryStatus::Clean = &cache_entry.status {
            return Err(StateManagerError::NotDirtyCache);
        }
        let write_op = cache_entry.as_merkle_state_mut(state_key)?;
        // Case 1: Trie is empty
        if self.merkle_db_read().root() == HASH32_EMPTY {
            // Initialize the empty merkle trie by committing the first entry.
            // This adds the first entry to the `MerkleDB`.
            // Additionally, it also adds the first entry to the `StateDB`
            // if the first entry of the merkle trie is the regular leaf node type.
            let (new_root, maybe_state_db_write) =
                self.merkle_db_read().commit_to_empty_trie(&write_op)?;

            // Update the merkle root of the MerkleDB
            self.merkle_db_write().update_root(new_root);

            // Add new entries to the StateDB (if exists)
            if let Some(state_db_write) = maybe_state_db_write {
                let state_db_write_batch_single =
                    StateDBWriteSet::new(HashMap::from([state_db_write.clone()]))
                        .generate_write_batch()?;
                self.state_db_read()
                    .commit_write_batch(state_db_write_batch_single)?;
            }

            return Ok(());
        }

        // Case 2: Trie is not empty

        let state_key = match &write_op {
            MerkleWriteOp::Add(k, _) => k,
            MerkleWriteOp::Update(k, _) => k,
            MerkleWriteOp::Remove(k) => k,
        };

        let mut affected_nodes_by_depth = AffectedNodesByDepth::default();
        self.merkle_db_read().collect_leaf_path(
            state_key,
            write_op.clone(),
            &mut affected_nodes_by_depth,
        )?;

        let MerkleWriteSet {
            merkle_db_write_set,
            state_db_write_set,
        } = affected_nodes_by_depth.generate_merkle_write_set()?;

        // Debugging
        // println!("AffectedNodesByDepth: ");
        // println!("{}", &affected_nodes_by_depth);
        // println!("MerkleDBWriteSet: ");
        // println!("{}", &merkle_db_write_set);
        // println!("StateDBWriteSet: ");
        // println!("{}", &state_db_write_set);

        self.merkle_db_read()
            .commit_nodes_write_batch(merkle_db_write_set.generate_write_batch()?)?;

        // Update the merkle root of the MerkleDB
        self.merkle_db_write()
            .update_root(merkle_db_write_set.get_new_root());
        println!(
            "Merkle root updated: {}",
            &merkle_db_write_set.get_new_root()
        );

        // Add new entries to the StateDB
        self.state_db_read()
            .commit_write_batch(state_db_write_set.generate_write_batch()?)?;

        // Mark committed entry as clean
        cache_entry.value_mut().mark_clean();

        Ok(())
    }

    /// Collects all dirty cache entries after state transition, then commit them into
    /// `MerkleDB` and `StateDB` as a single synchronous batch write operation.
    /// After commiting to the databases, marks the committed cache entries as clean.
    pub fn commit_dirty_cache(&self) -> Result<(), StateManagerError> {
        let dirty_entries = self.cache.collect_dirty();
        if dirty_entries.is_empty() {
            return Ok(());
        }

        let mut affected_nodes_by_depth = AffectedNodesByDepth::default();

        for (state_key, entry) in &dirty_entries {
            self.merkle_db_read().collect_leaf_path(
                state_key,
                entry.as_merkle_state_mut(state_key)?,
                &mut affected_nodes_by_depth,
            )?;
        }

        // Convert dirty cache entries into write batch and commit to the MerkleDB
        let MerkleWriteSet {
            merkle_db_write_set,
            state_db_write_set,
        } = affected_nodes_by_depth.generate_merkle_write_set()?;

        self.merkle_db_read()
            .commit_nodes_write_batch(merkle_db_write_set.generate_write_batch()?)?;

        // Update the merkle root of the MerkleDB
        self.merkle_db_write()
            .update_root(merkle_db_write_set.get_new_root());

        // Add new entries to the StateDB
        self.state_db_read()
            .commit_write_batch(state_db_write_set.generate_write_batch()?)?;

        // Mark committed entries as clean
        self.cache.mark_entries_clean(&dirty_entries);

        Ok(())
    }

    #[allow(dead_code)]
    fn commit_to_merkle_db() {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn commit_to_state_db() {
        unimplemented!()
    }

    fn insert_cache_entry<T>(&self, state_key: &Hash32, state_entry: T)
    where
        T: StateComponent,
    {
        let cache_entry = CacheEntry::new(T::into_entry_type(state_entry));
        self.cache.insert(*state_key, cache_entry);
    }

    //
    // Immutable/mutable references to state components and account storage entries
    //

    fn get_state_entry_internal<T>(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<T>, StateManagerError>
    where
        T: StateComponent,
    {
        // Check the cache
        if let Some(entry) = self.cache.get(state_key) {
            if let Some(state_entry) = T::from_entry_type(&entry.value) {
                return Ok(Some(state_entry.clone()));
            }
        }

        // Retrieve the state from the DB
        let Some(state_data) = self.retrieve_state_encoded(state_key)? else {
            return Ok(None);
        };

        let state_entry = T::decode(&mut state_data.as_slice())?;
        // Insert the entry into the cache
        self.insert_cache_entry(state_key, state_entry.clone());
        Ok(Some(state_entry))
    }

    fn with_mut_state_entry_internal<T, F>(
        &self,
        state_key: &Hash32,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: StateComponent,
        F: FnOnce(&mut T),
    {
        // Only `StateMut::Update` and `StateMut::Remove` are allowed.
        if let StateMut::Add = state_mut {
            return Err(StateManagerError::WrongStateMutType);
        }

        // Ensure the cache entry exists.
        // `StateMut::Update` and `StateMut::Remove` operations require initialized state entry.
        let state_exists = self.get_state_entry_internal::<T>(state_key)?.is_some();
        if !state_exists {
            return Err(StateManagerError::StateKeyNotInitialized);
        }

        let mut cache_entry = self
            .cache
            .get_mut(state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let Some(entry_mut) = T::from_entry_type_mut(&mut cache_entry.value) {
            f(entry_mut); // Call the closure to apply the state mutation
            cache_entry.mark_dirty(state_mut);
            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    fn add_state_entry_internal<T>(
        &self,
        state_key: &Hash32,
        state_entry: T,
    ) -> Result<(), StateManagerError>
    where
        T: StateComponent,
    {
        // Ensure the cache entry doesn't exist.
        let state_exists = self.get_state_entry_internal::<T>(state_key)?.is_some();
        // TODO: determine either to throw an error or silently run `Update` operation
        if state_exists {
            return Err(StateManagerError::StateEntryAlreadyExists);
        }

        self.cache.insert(
            *state_key,
            CacheEntry {
                value: state_entry.into_entry_type(),
                status: CacheEntryStatus::Dirty(StateMut::Add),
            },
        );

        Ok(())
    }

    fn get_simple_state_entry<T>(&self) -> Result<T, StateManagerError>
    where
        T: SimpleStateComponent,
    {
        self.get_state_entry_internal(&get_simple_state_key(T::STATE_KEY_CONSTANT))?
            .ok_or(StateManagerError::StateKeyNotInitialized) // simple state key must be initialized
    }

    fn with_mut_simple_state_entry<T, F>(
        &self,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: SimpleStateComponent,
        F: FnOnce(&mut T),
    {
        self.with_mut_state_entry_internal(
            &get_simple_state_key(T::STATE_KEY_CONSTANT),
            state_mut,
            f,
        )
    }

    fn add_simple_state_entry<T>(&self, state_entry: T) -> Result<(), StateManagerError>
    where
        T: SimpleStateComponent,
    {
        self.add_state_entry_internal(&get_simple_state_key(T::STATE_KEY_CONSTANT), state_entry)
    }

    fn get_account_state_entry<T>(&self, state_key: &Hash32) -> Result<Option<T>, StateManagerError>
    where
        T: AccountStateComponent,
    {
        self.get_state_entry_internal(state_key) // account state key could not be initialized yet
    }

    fn with_mut_account_state_entry<T, F>(
        &self,
        state_key: &Hash32,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: AccountStateComponent,
        F: FnOnce(&mut T),
    {
        self.with_mut_state_entry_internal(state_key, state_mut, f)
    }

    fn add_account_state_entry<T>(
        &self,
        state_key: &Hash32,
        state_entry: T,
    ) -> Result<(), StateManagerError>
    where
        T: AccountStateComponent,
    {
        self.add_state_entry_internal(state_key, state_entry)
    }

    impl_simple_state_accessors!(AuthPool, auth_pool);
    impl_simple_state_accessors!(AuthQueue, auth_queue);
    impl_simple_state_accessors!(BlockHistory, block_history);
    impl_simple_state_accessors!(SafroleState, safrole);
    impl_simple_state_accessors!(DisputesState, disputes);
    impl_simple_state_accessors!(EntropyAccumulator, entropy_accumulator);
    impl_simple_state_accessors!(StagingSet, staging_set);
    impl_simple_state_accessors!(ActiveSet, active_set);
    impl_simple_state_accessors!(PastSet, past_set);
    impl_simple_state_accessors!(PendingReports, pending_reports);
    impl_simple_state_accessors!(Timeslot, timeslot);
    impl_simple_state_accessors!(PrivilegedServices, privileged_services);
    impl_simple_state_accessors!(ValidatorStats, validator_stats);
    impl_simple_state_accessors!(AccumulateQueue, accumulate_queue);
    impl_simple_state_accessors!(AccumulateHistory, accumulate_history);

    pub fn get_account_metadata(
        &self,
        address: Address,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        let state_key = get_account_metadata_state_key(address);
        self.get_account_state_entry(&state_key)
    }

    pub fn with_mut_account_metadata<F>(
        &self,
        state_mut: StateMut,
        address: Address,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountMetadata),
    {
        let state_key = get_account_metadata_state_key(address);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
    }

    // TODO: Add method `add_account_metadata`

    /// Wrapper function of the `with_mut_account_metadata` to update account storage footprints
    /// when there is a change in the storage entries.
    pub fn update_account_storage_footprint(
        &self,
        address: Address,
        storage_key: &Hash32,
        new_storage_entry: &AccountStorageEntry,
    ) -> Result<(), StateManagerError> {
        let prev_storage_entry = self.get_account_storage_entry(address, storage_key)?;
        let (item_count_delta, octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_storage_entry.as_ref(),
                new_storage_entry,
            )
            .ok_or(StateManagerError::StorageEntryNotFound)?;

        let state_mut = match item_count_delta.cmp(&0) {
            Ordering::Greater => StateMut::Add,
            Ordering::Less => StateMut::Remove,
            Ordering::Equal => StateMut::Update,
        };

        // Update the footprints
        self.with_mut_account_metadata(state_mut, address, |metadata| {
            metadata.update_storage_items_count(item_count_delta);
            metadata.update_storage_total_octets(octets_count_delta);
        })
    }

    /// Wrapper function of the `with_mut_account_metadata` to update lookups footprints of the
    /// account metadata when there is a change in the lookups entries.
    pub fn update_account_lookups_footprint(
        &self,
        address: Address,
        lookups_key: &(Hash32, u32),
        new_lookups_entry: &AccountLookupsEntry,
    ) -> Result<(), StateManagerError> {
        let prev_lookups_entry = self.get_account_lookups_entry(address, lookups_key)?;

        // Construct `AccountLookupsOctetsUsage` types from the previous and the new entries.
        let prev_lookups_octets_usage = prev_lookups_entry.map(|p| AccountLookupsOctetsUsage {
            preimage_length: lookups_key.1,
            entry: p,
        });
        let new_lookups_octets_usage = AccountLookupsOctetsUsage {
            preimage_length: lookups_key.1,
            entry: new_lookups_entry.clone(),
        };

        let (item_count_delta, octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_lookups_octets_usage.as_ref(),
                &new_lookups_octets_usage,
            )
            .ok_or(StateManagerError::StorageEntryNotFound)?;

        let state_mut = match item_count_delta.cmp(&0) {
            Ordering::Greater => StateMut::Add,
            Ordering::Less => StateMut::Remove,
            Ordering::Equal => StateMut::Update,
        };

        // Update the footprints
        self.with_mut_account_metadata(state_mut, address, |metadata| {
            metadata.update_lookups_items_count(item_count_delta);
            metadata.update_lookups_total_octets(octets_count_delta);
        })?;

        Ok(())
    }

    pub fn get_account_storage_entry(
        &self,
        address: Address,
        storage_key: &Hash32,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        let state_key = get_account_storage_state_key(address, storage_key);
        self.get_account_state_entry(&state_key)
    }

    pub fn with_mut_account_storage_entry<F>(
        &self,
        state_mut: StateMut,
        address: Address,
        storage_key: &Hash32,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountStorageEntry),
    {
        let state_key = get_account_storage_state_key(address, storage_key);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
    }

    pub fn add_account_storage_entry(
        &self,
        address: Address,
        storage_key: &Hash32,
        storage_entry: AccountStorageEntry,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_storage_state_key(address, storage_key);
        self.add_account_state_entry(&state_key, storage_entry)
    }

    pub fn get_account_preimages_entry(
        &self,
        address: Address,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        let state_key = get_account_preimage_state_key(address, preimages_key);
        self.get_account_state_entry(&state_key)
    }

    pub fn with_mut_account_preimages_entry<F>(
        &self,
        state_mut: StateMut,
        address: Address,
        preimages_key: &Hash32,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountPreimagesEntry),
    {
        let state_key = get_account_preimage_state_key(address, preimages_key);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
    }

    pub fn add_account_preimages_entry(
        &self,
        address: Address,
        preimages_key: &Hash32,
        preimages_entry: AccountPreimagesEntry,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_preimage_state_key(address, preimages_key);
        self.add_account_state_entry(&state_key, preimages_entry)
    }

    pub fn get_account_lookups_entry(
        &self,
        address: Address,
        lookups_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let (h, l) = lookups_key;
        let state_key = get_account_lookups_state_key(address, h, *l)?;
        self.get_account_state_entry(&state_key)
    }

    pub fn with_mut_account_lookups_entry<F>(
        &self,
        state_mut: StateMut,
        address: Address,
        lookups_key: (&Hash32, u32),
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountLookupsEntry),
    {
        let (h, l) = lookups_key;
        let state_key = get_account_lookups_state_key(address, h, l)?;
        self.with_mut_account_state_entry(&state_key, state_mut, f)
    }

    pub fn add_account_lookups_entry(
        &self,
        address: Address,
        lookups_key: (&Hash32, u32),
        lookups_entry: AccountLookupsEntry,
    ) -> Result<(), StateManagerError> {
        let (h, l) = lookups_key;
        let state_key = get_account_lookups_state_key(address, h, l)?;
        self.add_account_state_entry(&state_key, lookups_entry)
    }
}
