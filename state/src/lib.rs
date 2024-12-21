use dashmap::DashMap;
use rjam_codec::{JamCodecError, JamDecode};
use rjam_common::{Address, Hash32, Octets};
use rjam_db::{KeyValueDBError, StateDB};
use rjam_state_merkle::{error::StateMerkleError, merkle_db::MerkleDB, types::LeafType};
use rjam_types::{
    state::*,
    state_utils::{
        get_account_lookups_state_key, get_account_metadata_state_key,
        get_account_storage_state_key, get_simple_state_key, StateComponent, StateEntryType,
        StateKeyConstant,
    },
};
use std::{cmp::Ordering, sync::Arc};
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

pub enum CacheEntryStatus {
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
        let state_key = get_simple_state_key(state_key_constant);
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
        if let Some(merkle_db) = &self.merkle_db {
            let (leaf_type, state_data) = match merkle_db.retrieve(state_key.as_slice())? {
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

    pub fn get_auth_pool(&self) -> Result<AuthPool, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_auth_pool<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AuthPool),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_auth_queue(&self) -> Result<AuthQueue, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_auth_queue<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AuthQueue),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_block_history(&self) -> Result<BlockHistory, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_block_history<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut BlockHistory),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_safrole(&self) -> Result<SafroleState, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_safrole<F>(&self, write_op: StateWriteOp, f: F) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut SafroleState),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_disputes(&self) -> Result<DisputesState, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_disputes<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut DisputesState),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_entropy_accumulator(&self) -> Result<EntropyAccumulator, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_entropy_accumulator<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut EntropyAccumulator),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_staging_set(&self) -> Result<StagingSet, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_staging_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut StagingSet),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_active_set(&self) -> Result<ActiveSet, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_active_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut ActiveSet),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_past_set(&self) -> Result<PastSet, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_past_set<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PastSet),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_pending_reports(&self) -> Result<PendingReports, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_pending_reports<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PendingReports),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_timeslot(&self) -> Result<Timeslot, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_timeslot<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut Timeslot),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_privileged_services(&self) -> Result<PrivilegedServices, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_privileged_services<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut PrivilegedServices),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_validator_stats(&self) -> Result<ValidatorStats, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_validator_stats<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut ValidatorStats),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_accumulate_queue(&self) -> Result<AccumulateQueue, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_accumulate_queue<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccumulateQueue),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_accumulate_history(&self) -> Result<AccumulateHistory, StateManagerError> {
        self.get_state_entry()
    }

    pub fn with_mut_accumulate_history<F>(
        &self,
        write_op: StateWriteOp,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccumulateHistory),
    {
        self.with_mut_state_entry(write_op, f)
    }

    pub fn get_account_metadata(
        &self,
        address: Address,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        let state_key = get_account_metadata_state_key(StateKeyConstant::AccountMetadata, address);

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
        let state_key = get_account_metadata_state_key(StateKeyConstant::AccountMetadata, address);

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
        let (item_count_delta, octets_count_delta) =
            AccountMetadata::calculate_storage_footprint_delta(
                prev_lookups_entry.as_ref(),
                new_lookups_entry,
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

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountStorageEntry(storage_entry) = entry_ref.value.clone() {
                return Ok(Some(storage_entry));
            }
        }

        // Retrieve the state from the DB
        let storage_entry = AccountStorageEntry {
            key: *storage_key,
            value: match self.retrieve_state_encoded(&state_key)? {
                Some(state_data) => Octets::from_vec(state_data),
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
        let state_key = get_account_storage_state_key(address, storage_key);

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
        let state_key = get_account_storage_state_key(address, preimages_key);

        // Check the cache
        if let Some(entry_ref) = self.cache.get(&state_key) {
            if let StateEntryType::AccountPreimagesEntry(preimages_entry) = entry_ref.value.clone()
            {
                return Ok(Some(preimages_entry));
            }
        }

        // Retrieve the state from the DB
        let preimages_entry = AccountPreimagesEntry {
            key: *preimages_key,
            value: match self.retrieve_state_encoded(&state_key)? {
                Some(state_data) => Octets::from_vec(state_data),
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
        let state_key = get_account_storage_state_key(address, preimages_key);

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
        lookups_key: &(Hash32, u32),
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let (h, l) = lookups_key;
        let state_key = get_account_lookups_state_key(address, h, *l)?;

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
        let state_key = get_account_lookups_state_key(address, h, l)?;

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
