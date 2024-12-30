use dashmap::DashMap;
use rjam_codec::JamCodecError;
use rjam_common::{Address, Hash32, Octets};
use rjam_crypto::CryptoError;
use rjam_db::{KeyValueDBError, StateDB};
use rjam_state_merkle::{error::StateMerkleError, merkle_db::MerkleDB, types::LeafType};
use rjam_types::{
    state::*,
    state_utils::{
        get_account_lookups_state_key, get_account_metadata_state_key,
        get_account_preimage_state_key, get_account_storage_state_key, get_simple_state_key,
        AccountStateComponent, StateComponent, StateEntryType, StateKeyConstant,
    },
};
use std::{
    cmp::Ordering,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateManagerError {
    #[error("State key not initialized")]
    StateKeyNotInitialized,
    #[error("Cache entry not found")]
    CacheEntryNotFound,
    #[error("Unexpected entry type")]
    UnexpectedEntryType,
    #[error("Account not found")]
    AccountNotFound,
    #[error("Account storage dictionary entry not found")]
    StorageEntryNotFound,
    #[error("Account lookups dictionary entry not found")]
    LookupsEntryNotFound,
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Merkle error: {0}")]
    StateMerkleError(#[from] StateMerkleError),
    #[error("KeyValueDB error: {0}")]
    KeyValueDBError(#[from] KeyValueDBError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Clone)]
pub enum StateWriteOp {
    Add,
    Update,
    Upsert,
    Remove,
}

#[derive(Clone)]
pub enum CacheEntryStatus {
    Clean,
    Dirty(StateWriteOp),
}

#[derive(Clone)]
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

    #[allow(dead_code)]
    fn is_dirty(&self) -> bool {
        matches!(self.status, CacheEntryStatus::Dirty(_))
    }

    fn mark_dirty(&mut self, write_op: StateWriteOp) {
        self.status = CacheEntryStatus::Dirty(write_op);
    }

    #[allow(dead_code)]
    fn mark_clean(&mut self) {
        self.status = CacheEntryStatus::Clean;
    }
}

struct StateCache {
    inner: Arc<DashMap<Hash32, CacheEntry>>,
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

    #[allow(dead_code)]
    fn collect_dirty(&self) -> Result<Vec<(Hash32, CacheEntry)>, StateManagerError> {
        Ok(self
            .inner
            .iter()
            .filter_map(|entry_ref| match entry_ref.value().status {
                CacheEntryStatus::Clean => None,
                CacheEntryStatus::Dirty(_) => Some((*entry_ref.key(), entry_ref.value().clone())),
            })
            .collect())
    }
}

pub struct StateManager {
    state_db: Arc<StateDB>,
    merkle_db: Arc<MerkleDB>,
    cache: StateCache,
}

macro_rules! impl_state_accessors {
    ($state_type:ty, $fn_type:ident) => {
        paste::paste! {
            pub fn [<get_ $fn_type>](&self) -> Result<$state_type, StateManagerError> {
                self.get_state_entry()
            }

            pub fn [<with_mut_ $fn_type>]<F>(
                &self,
                write_op: StateWriteOp,
                f: F,
            ) -> Result<(), StateManagerError>
            where
                F: FnOnce(&mut $state_type),
            {
                self.with_mut_state_entry(write_op, f)
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

    pub fn new(state_db: Arc<StateDB>, merkle_db: Arc<MerkleDB>) -> Self {
        Self {
            state_db,
            merkle_db,
            cache: StateCache::new(),
        }
    }

    fn get_merkle_db(&self) -> Arc<MerkleDB> {
        self.merkle_db.clone()
    }

    fn get_state_db(&self) -> Arc<StateDB> {
        self.state_db.clone()
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

    fn retrieve_state_encoded(
        &self,
        state_key: &Hash32,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        let Some((leaf_type, state_data)) = self.get_merkle_db().retrieve(state_key.as_slice())?
        else {
            return Ok(None);
        };

        let state_data = match leaf_type {
            LeafType::Embedded => state_data,
            LeafType::Regular => {
                let Some(entry) = self.get_state_db().get_entry(&state_data)? else {
                    return Ok(None);
                };
                entry
            }
        };

        Ok(Some(state_data))
    }

    #[allow(dead_code)]
    fn insert_cache_entry() {
        todo!()
    }

    //
    // Immutable/mutable references to state components and account storage entries
    //

    fn get_state_entry<T>(&self) -> Result<T, StateManagerError>
    where
        T: StateComponent,
    {
        let state_key = get_simple_state_key(T::STATE_KEY_CONSTANT);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let Some(state_entry) = T::from_entry_type(&entry_ref.value) {
                return Ok(state_entry.clone());
            }
        }

        // Retrieve the state from the DB
        let state_data = self
            .retrieve_state_encoded(&state_key)?
            .ok_or(StateManagerError::StateKeyNotInitialized)?;
        let state_entry = T::decode(&mut state_data.as_slice())?;

        // Insert the entry into the cache
        let cache_entry = CacheEntry::new(T::into_entry_type(state_entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(state_entry)
    }

    fn with_mut_state_entry<T, F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: StateComponent,
        F: FnOnce(&mut T),
    {
        let state_key = get_simple_state_key(T::STATE_KEY_CONSTANT);

        // FIXME: Load data from DB if cache not found
        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let Some(state_entry_mut) = T::from_entry_type_mut(&mut cache_entry.value) {
            f(state_entry_mut); // Call the closure to apply the state mutation
            cache_entry.mark_dirty(write_op);
            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    fn get_account_state_entry<T>(&self, state_key: Hash32) -> Result<Option<T>, StateManagerError>
    where
        T: AccountStateComponent,
    {
        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let Some(state_entry) = T::from_entry_type(&entry_ref.value) {
                return Ok(Some(state_entry.clone()));
            }
        }

        // Retrieve the state from the DB
        let state_data = match self.retrieve_state_encoded(&state_key)? {
            Some(state_data) => Octets::from_vec(state_data),
            None => return Ok(None),
        };
        let entry = T::decode(&mut state_data.as_slice())?;

        // Insert the entry into the cache
        let cache_entry = CacheEntry::new(T::into_entry_type(entry.clone()));
        self.cache.insert(state_key, cache_entry);

        Ok(Some(entry))
    }

    fn with_mut_account_state_entry<T, F>(
        &self,
        state_key: Hash32,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: AccountStateComponent,
        F: FnOnce(&mut T),
    {
        // FIXME: Load data from DB if cache not found
        let mut cache_entry = self
            .cache
            .get_mut(&state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let Some(entry_mut) = T::from_entry_type_mut(&mut cache_entry.value) {
            f(entry_mut); // Call the closure to apply the state mutation
            cache_entry.mark_dirty(write_op);
            Ok(())
        } else {
            Err(StateManagerError::UnexpectedEntryType)
        }
    }

    impl_state_accessors!(AuthPool, auth_pool);
    impl_state_accessors!(AuthQueue, auth_queue);
    impl_state_accessors!(BlockHistory, block_history);
    impl_state_accessors!(SafroleState, safrole);
    impl_state_accessors!(DisputesState, disputes);
    impl_state_accessors!(EntropyAccumulator, entropy_accumulator);
    impl_state_accessors!(StagingSet, staging_set);
    impl_state_accessors!(ActiveSet, active_set);
    impl_state_accessors!(PastSet, past_set);
    impl_state_accessors!(PendingReports, pending_reports);
    impl_state_accessors!(Timeslot, timeslot);
    impl_state_accessors!(PrivilegedServices, privileged_services);
    impl_state_accessors!(ValidatorStats, validator_stats);
    impl_state_accessors!(AccumulateQueue, accumulate_queue);
    impl_state_accessors!(AccumulateHistory, accumulate_history);

    pub fn get_account_metadata(
        &self,
        address: Address,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        let state_key = get_account_metadata_state_key(address);
        self.get_account_state_entry(state_key)
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
        let state_key = get_account_metadata_state_key(address);
        self.with_mut_account_state_entry(state_key, write_op, f)
    }

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

        let write_op = match item_count_delta.cmp(&0) {
            Ordering::Greater => StateWriteOp::Add,
            Ordering::Less => StateWriteOp::Remove,
            Ordering::Equal => StateWriteOp::Update,
        };

        // Update the footprints
        self.with_mut_account_metadata(write_op, address, |metadata| {
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

        let write_op = match item_count_delta.cmp(&0) {
            Ordering::Greater => StateWriteOp::Add,
            Ordering::Less => StateWriteOp::Remove,
            Ordering::Equal => StateWriteOp::Update,
        };

        // Update the footprints
        self.with_mut_account_metadata(write_op, address, |metadata| {
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
        self.get_account_state_entry(state_key)
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
        let state_key = get_account_storage_state_key(address, storage_key);
        self.with_mut_account_state_entry(state_key, write_op, f)
    }

    pub fn get_account_preimages_entry(
        &self,
        address: Address,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        let state_key = get_account_preimage_state_key(address, preimages_key);
        self.get_account_state_entry(state_key)
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
        let state_key = get_account_preimage_state_key(address, preimages_key);
        self.with_mut_account_state_entry(state_key, write_op, f)
    }

    pub fn get_account_lookups_entry(
        &self,
        address: Address,
        lookups_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let (h, l) = lookups_key;
        let state_key = get_account_lookups_state_key(address, h, *l)?;
        self.get_account_state_entry(state_key)
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
        let state_key = get_account_lookups_state_key(address, h, l)?;
        self.with_mut_account_state_entry(state_key, write_op, f)
    }
}
