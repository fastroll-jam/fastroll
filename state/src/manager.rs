use crate::{
    cache::{CacheEntry, CacheEntryStatus, StateCache, StateMut},
    error::StateManagerError,
    provider::HostStateProvider,
    state_db::StateDB,
    state_utils::{
        get_account_lookups_state_key, get_account_metadata_state_key,
        get_account_preimage_state_key, get_account_storage_state_key, get_simple_state_key,
        AccountStateComponent, SimpleStateComponent, StateComponent, StateEntryType,
    },
    types::{
        privileges::PrivilegedServices, AccountCode, AccountLookupsEntry, AccountMetadata,
        AccountPreimagesEntry, AccountStorageEntry, AccumulateHistory, AccumulateQueue, ActiveSet,
        AuthPool, AuthQueue, BlockHistory, DisputesState, EpochEntropy, LastAccumulateOutputs,
        OnChainStatistics, PastSet, PendingReports, SafroleState, SlotSealer, StagingSet, Timeslot,
    },
};
use async_trait::async_trait;
use fr_codec::prelude::*;
use fr_common::{
    CodeHash, LookupsKey, MerkleRoot, Octets, PreimagesKey, ServiceId, StateKey, StorageKey,
    TimeslotIndex,
};
use fr_config::StorageConfig;
use fr_crypto::octets_to_hash32;
use fr_db::{core::core_db::CoreDB, WriteBatch};
use fr_state_merkle::{
    error::StateMerkleError,
    merkle_db::MerkleDB,
    types::nodes::LeafType,
    write_set::{DBWriteSet, MerkleDBWriteSet, StateDBWriteSet},
};
use std::{collections::HashMap, future::Future, sync::Arc};
use tracing::instrument;

pub struct StateManager {
    state_db: StateDB,
    merkle_db: MerkleDB,
    cache: StateCache,
}

macro_rules! impl_simple_state_accessors {
    ($state_type:ty, $fn_type:ident) => {
        paste::paste! {
            pub async fn [<get_ $fn_type>](&self) -> Result<$state_type, StateManagerError> {
                self.get_simple_state_entry().await
            }

            pub async fn [<get_ $fn_type _clean>](&self) -> Result<$state_type, StateManagerError> {
                self.get_clean_simple_state_entry().await
            }

            pub async fn [<with_mut_ $fn_type>]<F, E>(
                &self,
                state_mut: StateMut,
                f: F,
            ) -> Result<(), StateManagerError>
            where
                F: FnOnce(&mut $state_type) -> Result<(), E>,
                StateManagerError: From<E>
            {
                self.with_mut_simple_state_entry(state_mut, f).await
            }

            pub async fn [<add_ $fn_type>](&self, state_entry: $state_type) -> Result<(), StateManagerError> {
                self.add_simple_state_entry(state_entry).await
            }
        }
    };
}

#[async_trait]
impl HostStateProvider for StateManager {
    async fn get_privileged_services(&self) -> Result<PrivilegedServices, StateManagerError> {
        self.get_privileged_services().await
    }

    async fn get_auth_queue(&self) -> Result<AuthQueue, StateManagerError> {
        self.get_auth_queue().await
    }

    async fn account_exists(&self, service_id: ServiceId) -> Result<bool, StateManagerError> {
        self.account_exists(service_id).await
    }

    async fn check(&self, service_id: ServiceId) -> Result<ServiceId, StateManagerError> {
        self.check(service_id).await
    }

    async fn get_account_metadata(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        self.get_account_metadata(service_id).await
    }

    async fn get_account_storage_entry(
        &self,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        self.get_account_storage_entry(service_id, storage_key)
            .await
    }

    async fn get_account_preimages_entry(
        &self,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        self.get_account_preimages_entry(service_id, preimages_key)
            .await
    }

    async fn get_account_lookups_entry(
        &self,
        service_id: ServiceId,
        lookups_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        self.get_account_lookups_entry(service_id, lookups_key)
            .await
    }

    async fn lookup_historical_preimage(
        &self,
        service_id: ServiceId,
        reference_timeslot: &Timeslot,
        preimage_hash: &PreimagesKey,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        self.lookup_historical_preimage(service_id, reference_timeslot, preimage_hash)
            .await
    }
}

impl StateManager {
    pub fn from_core_db(core_db: Arc<CoreDB>, cfg: &StorageConfig) -> Self {
        Self::new(
            StateDB::new(
                core_db.clone(),
                cfg.cfs.state_db.cf_name,
                cfg.cfs.state_db.cache_size,
            ),
            MerkleDB::new(
                core_db,
                cfg.cfs.merkle_db.cf_name,
                cfg.cfs.merkle_db.cache_size,
            ),
            StateCache::new(cfg.state_cache_size),
        )
    }

    pub fn new(state_db: StateDB, merkle_db: MerkleDB, cache: StateCache) -> Self {
        Self {
            state_db,
            merkle_db,
            cache,
        }
    }

    pub async fn get_raw_state_entry(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        // Check the cache
        if let Some(entry) = self.cache.get_entry(state_key) {
            if let StateEntryType::Raw(octets) = entry.value.as_ref() {
                return Ok(Some(octets.clone().into_vec()));
            }
        }
        self.retrieve_state_encoded(state_key).await
    }

    /// Always retrieves state entry from the DB for test purpose.
    pub async fn get_raw_state_entry_from_db(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        self.retrieve_state_encoded(state_key).await
    }

    pub async fn add_raw_state_entry(
        &self,
        state_key: &StateKey,
        state_val: Vec<u8>,
    ) -> Result<(), StateManagerError> {
        // State entry must not exist to be added
        let state_exists = self.get_raw_state_entry_from_db(state_key).await?.is_some();
        if state_exists {
            return Err(StateManagerError::StateEntryAlreadyExists);
        }

        self.cache.insert_entry(
            state_key.clone(),
            CacheEntry {
                clean_snapshot: Arc::new(StateEntryType::Raw(Octets::from_vec(state_val.clone()))),
                value: Arc::new(StateEntryType::Raw(Octets::from_vec(state_val))),
                status: CacheEntryStatus::Dirty(StateMut::Add),
            },
        );
        Ok(())
    }

    pub async fn update_raw_state_entry(
        &self,
        state_key: &StateKey,
        new_val: Vec<u8>,
    ) -> Result<(), StateManagerError> {
        // State entry must exist to be updated
        let old_state = self.get_raw_state_entry_from_db(state_key).await?.ok_or(
            StateManagerError::StateKeyNotInitialized(state_key.encode_hex()),
        )?;
        self.cache.insert_entry(
            state_key.clone(),
            CacheEntry {
                clean_snapshot: Arc::new(StateEntryType::Raw(Octets::from_vec(old_state))),
                value: Arc::new(StateEntryType::Raw(Octets::from_vec(new_val))),
                status: CacheEntryStatus::Dirty(StateMut::Update),
            },
        );
        Ok(())
    }

    pub async fn remove_raw_state_entry(
        &self,
        state_key: &StateKey,
    ) -> Result<(), StateManagerError> {
        // State entry must exist to be removed
        let old_state = self.get_raw_state_entry_from_db(state_key).await?.ok_or(
            StateManagerError::StateKeyNotInitialized(state_key.encode_hex()),
        )?;
        self.cache.insert_entry(
            state_key.clone(),
            CacheEntry {
                value: Arc::new(StateEntryType::Raw(Octets::default())),
                clean_snapshot: Arc::new(StateEntryType::Raw(Octets::from_vec(old_state))),
                status: CacheEntryStatus::Dirty(StateMut::Remove),
            },
        );
        Ok(())
    }

    fn get_clean_cache_snapshot_as_state<T>(&self, state_key: &StateKey) -> Option<T>
    where
        T: StateComponent,
    {
        if let Some(entry) = self.cache.get_entry(state_key) {
            if let Some(state_entry) = T::from_entry_type(&entry.clean_snapshot) {
                return Some(state_entry.clone());
            }
        }
        None
    }

    pub fn get_cache_entry_as_state<T>(&self, state_key: &StateKey) -> Option<T>
    where
        T: StateComponent,
    {
        if let Some(entry) = self.cache.get_entry(state_key) {
            if let Some(state_entry) = T::from_entry_type(&entry.value) {
                return Some(state_entry.clone());
            }
        }
        None
    }

    fn insert_clean_cache_entry_and_snapshot<T>(&self, state_key: &StateKey, state_entry: T)
    where
        T: StateComponent,
    {
        self.cache.insert_entry(
            state_key.clone(),
            CacheEntry::new(T::into_entry_type(state_entry)),
        );
    }

    pub fn clear_state_cache(&self) {
        self.cache.invalidate_all();
    }

    pub fn merkle_root(&self) -> MerkleRoot {
        self.merkle_db.root()
    }

    pub async fn account_exists(&self, service_id: ServiceId) -> Result<bool, StateManagerError> {
        Ok(self.get_account_metadata(service_id).await?.is_some())
    }

    pub async fn check_impl<F, Fut>(
        service_id: ServiceId,
        account_exists_in_state: F,
    ) -> Result<ServiceId, StateManagerError>
    where
        F: Fn(ServiceId) -> Fut,
        Fut: Future<Output = Result<bool, StateManagerError>>,
    {
        let mut check_id = service_id;
        loop {
            if !account_exists_in_state(check_id).await? {
                return Ok(check_id);
            }
            check_id =
                ((check_id as u64 - (1 << 8) + 1) % ((1 << 32) - (1 << 9)) + (1 << 8)) as ServiceId;
        }
    }

    pub async fn check(&self, service_id: ServiceId) -> Result<ServiceId, StateManagerError> {
        Self::check_impl(service_id, |id| self.account_exists(id)).await
    }

    pub async fn get_account_code_hash(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<CodeHash>, StateManagerError> {
        Ok(self
            .get_account_metadata(service_id)
            .await?
            .map(|metadata| metadata.code_hash))
    }

    /// Retrieves service account code (preimage of the code hash)
    /// directly from the account preimage storage.
    ///
    /// Used by on-chain PVM invocations (`accumulate` and `on-transfer`) where direct access to
    /// on-chain state is possible.
    pub async fn get_account_code(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountCode>, StateManagerError> {
        let Some(metadata) = self.get_account_metadata(service_id).await? else {
            tracing::warn!("Account with service id {service_id} not found");
            return Ok(None);
        };
        tracing::debug!("Code hash: {}", &metadata.code_hash.encode_hex());
        let code_preimage = self
            .get_account_preimages_entry(service_id, &metadata.code_hash)
            .await?;
        Ok(code_preimage
            .map(|code| AccountCode::decode(&mut code.value.as_slice()))
            .transpose()?)
    }

    /// Retrieves service account code (preimage of the code hash)
    /// by utilizing the historical lookup function.
    ///
    /// Used by off-chain/in-core PVM invocations (`is-authorized` and `refine`) where direct access
    /// to on-chain state is not possible.
    pub async fn get_account_code_by_lookup(
        &self,
        service_id: ServiceId,
        reference_timeslot_index: TimeslotIndex,
        code_hash: &CodeHash,
    ) -> Result<Option<AccountCode>, StateManagerError> {
        let code_preimage = self
            .lookup_historical_preimage(service_id, &Timeslot(reference_timeslot_index), code_hash)
            .await?;
        Ok(code_preimage
            .map(|code| AccountCode::decode(&mut code.as_slice()))
            .transpose()?)
    }

    /// The historical lookup function `Λ`
    pub async fn lookup_historical_preimage(
        &self,
        service_id: ServiceId,
        reference_timeslot: &Timeslot,
        preimage_hash: &PreimagesKey,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        let preimage = match self
            .get_account_preimages_entry(service_id, preimage_hash)
            .await?
        {
            Some(preimage) => preimage.value,
            None => return Ok(None),
        };
        let preimage_length = preimage.len() as u32;
        let lookup_timeslots = match self
            .get_account_lookups_entry(service_id, &(preimage_hash.clone(), preimage_length))
            .await?
        {
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

    pub async fn get_slot_sealer(&self) -> Result<SlotSealer, StateManagerError> {
        let timeslot = self.get_timeslot().await?;
        Ok(self
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(&timeslot))
    }

    pub async fn retrieve_state_encoded(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        let retrieved = match self.merkle_db.retrieve(state_key).await {
            Ok(val) => val,
            Err(_) => return Ok(None),
        };

        let Some((leaf_type, state_data_or_hash)) = retrieved else {
            return Ok(None);
        };

        let state_data = match leaf_type {
            LeafType::Embedded => state_data_or_hash,
            LeafType::Regular => {
                // The state data hash is used as the key in the StateDB
                let Some(entry) = self
                    .state_db
                    .get_entry(&octets_to_hash32(&state_data_or_hash).ok_or(
                        StateManagerError::StateMerkleError(StateMerkleError::InvalidHash32Input),
                    )?)
                    .await?
                else {
                    return Ok(None);
                };
                entry
            }
        };

        Ok(Some(state_data))
    }

    fn append_to_merkle_db_write_batch(
        &self,
        batch: &mut WriteBatch,
        write_set: &MerkleDBWriteSet,
    ) -> Result<(), StateManagerError> {
        let merkle_cf = self.merkle_db.cf_handle()?;
        for (k, v) in write_set.entries() {
            batch.put_cf(&merkle_cf, k.as_slice(), v);
        }
        Ok(())
    }

    fn append_to_state_db_write_batch(
        &self,
        batch: &mut WriteBatch,
        write_set: &StateDBWriteSet,
    ) -> Result<(), StateManagerError> {
        let state_cf = self.state_db.cf_handle()?;
        for (k, v) in write_set.entries() {
            batch.put_cf(&state_cf, k.as_slice(), v);
        }
        Ok(())
    }

    /// Commits a single dirty cache entry into `MerkleDB` and `StateDB`.
    pub async fn commit_single_dirty_cache(
        &self,
        state_key: &StateKey,
    ) -> Result<(), StateManagerError> {
        let entry_status = self
            .cache
            .get_entry_status(state_key)
            .ok_or(StateManagerError::CacheEntryNotFound)?;

        if let CacheEntryStatus::Clean = entry_status {
            return Err(StateManagerError::NotDirtyCache);
        }
        let write_op = self.cache.get_entry_as_merkle_write_op(state_key)?;

        // Case 1: Trie is empty
        if self.merkle_db.root() == MerkleRoot::default() {
            // Initialize the empty merkle trie by committing the first entry.
            // This adds the first entry to the `MerkleDB`.
            // Additionally, it also adds the first entry to the `StateDB`
            // if the first entry of the merkle trie is the regular leaf node type.
            let (new_root, maybe_state_db_write) =
                self.merkle_db.commit_to_empty_trie(&write_op).await?;

            // Update the merkle root of the MerkleDB
            self.merkle_db.update_root(new_root);

            // Add new entries to the StateDB (if exists)
            if let Some(state_db_write) = maybe_state_db_write {
                let state_db_write_set =
                    StateDBWriteSet::new(HashMap::from([state_db_write.clone()]));
                let mut state_db_write_batch_single = WriteBatch::default();
                self.append_to_state_db_write_batch(
                    &mut state_db_write_batch_single,
                    &state_db_write_set,
                )?;
                self.commit_to_state_db(state_db_write_batch_single).await?;
            }

            // Mark committed entry as clean
            self.cache.mark_entry_clean_and_snapshot(state_key)?;
            return Ok(());
        }

        // Case 2: Trie is not empty
        let DBWriteSet {
            merkle_db_write_set,
            state_db_write_set,
        } = self
            .merkle_db
            .collect_write_set(state_key, write_op)
            .await?;

        // Debugging
        tracing::trace!("MerkleDBWriteSet: {}", &merkle_db_write_set);
        tracing::trace!("StateDBWriteSet: {}", &state_db_write_set);

        // Commit the write batch to the MerkleDB
        let mut merkle_db_wb = WriteBatch::default();
        self.append_to_merkle_db_write_batch(&mut merkle_db_wb, &merkle_db_write_set)?;
        self.commit_to_merkle_db(merkle_db_wb).await?;

        // Commit the write batch to the StateDB
        let mut state_db_wb = WriteBatch::default();
        self.append_to_state_db_write_batch(&mut state_db_wb, &state_db_write_set)?;
        self.commit_to_state_db(state_db_wb).await?;

        // Update the merkle root of the MerkleDB
        self.merkle_db
            .update_root(merkle_db_write_set.get_new_root().clone());
        tracing::trace!(
            "Merkle root updated: {}",
            &merkle_db_write_set.get_new_root()
        );

        // Mark committed entry as clean
        self.cache.mark_entry_clean_and_snapshot(state_key)?;
        Ok(())
    }

    /// Collects all dirty cache entries after state transition, then commit them into
    /// `MerkleDB` and `StateDB` as a single synchronous batch write operation.
    /// After committing to the databases, marks the committed cache entries as clean.
    #[instrument(level = "debug", skip(self))]
    pub async fn commit_dirty_cache(&self) -> Result<(), StateManagerError> {
        let mut dirty_entries = self.cache.collect_dirty();
        tracing::debug!("committing {} dirty cache entries", dirty_entries.len());
        if dirty_entries.is_empty() {
            return Ok(());
        }

        // If the trie is empty, process one dirty cache entry by calling `commit_single_dirty_cache`
        // to initialize the trie.
        if self.merkle_db.root() == MerkleRoot::default() {
            let (state_key, _entry) = dirty_entries.pop().expect("should not be empty");
            self.commit_single_dirty_cache(&state_key).await?;
            if dirty_entries.is_empty() {
                return Ok(());
            }
        };

        let mut merkle_db_wb = WriteBatch::default();
        let mut state_db_wb = WriteBatch::default();

        tracing::debug!("collecting DB write set");
        for (state_key, entry) in &dirty_entries {
            // Convert dirty cache entries into write batch and commit to the MerkleDB
            let DBWriteSet {
                merkle_db_write_set,
                state_db_write_set,
            } = self
                .merkle_db
                .collect_write_set(state_key, entry.as_merkle_write_op(state_key)?)
                .await?;

            // Debugging
            tracing::trace!("MerkleDBWriteSet: {}", &merkle_db_write_set);
            tracing::trace!("StateDBWriteSet: {}", &state_db_write_set);

            self.append_to_merkle_db_write_batch(&mut merkle_db_wb, &merkle_db_write_set)?;
            self.append_to_state_db_write_batch(&mut state_db_wb, &state_db_write_set)?;

            // Copy MerkleDBWriteSet entries to the WorkingSet
            merkle_db_write_set
                .iter()
                .for_each(|(_node_hash, node_write)| {
                    self.merkle_db
                        .working_set
                        .insert_node(node_write.clone().into());
                });

            // Update the WorkingSet root
            self.merkle_db
                .update_root(merkle_db_write_set.get_new_root().clone());
            tracing::trace!(
                "Merkle root updated: {}",
                &merkle_db_write_set.get_new_root()
            );
        }

        // Commit the write batch to the MerkleDB
        self.commit_to_merkle_db(merkle_db_wb).await?;

        // Commit the write batch to the StateDB
        self.commit_to_state_db(state_db_wb).await?;

        // Update the merkle root of the MerkleDB
        let new_root = self.merkle_db.root_with_working_set();
        self.merkle_db.update_root(new_root);

        // Clear the WorkingSet
        self.merkle_db.clear_working_set();

        // Sync up the state cache with the global state.
        self.cache.sync_cache_status(&dirty_entries);

        Ok(())
    }

    async fn commit_to_merkle_db(&self, batch: WriteBatch) -> Result<(), StateManagerError> {
        self.merkle_db.commit_write_batch(batch).await?;
        Ok(())
    }

    async fn commit_to_state_db(&self, batch: WriteBatch) -> Result<(), StateManagerError> {
        self.state_db.commit_write_batch(batch).await?;
        Ok(())
    }

    /// Gets a state entry prior to state mutation, by either referencing `clean_snapshot` of
    /// state cache or directly retrieving the clean value from the DB.
    async fn get_clean_state_entry_internal<T>(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<T>, StateManagerError>
    where
        T: StateComponent,
    {
        // Check the cache
        if let Some(clean_snapshot) = self.get_clean_cache_snapshot_as_state(state_key) {
            return Ok(Some(clean_snapshot));
        }

        // Retrieve the state from the DB
        let Some(state_data) = self.retrieve_state_encoded(state_key).await? else {
            return Ok(None);
        };

        let state_entry = T::decode(&mut state_data.as_slice())?;
        // Insert the entry into the cache
        self.insert_clean_cache_entry_and_snapshot(state_key, state_entry.clone());
        Ok(Some(state_entry))
    }

    async fn get_state_entry_internal<T>(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<T>, StateManagerError>
    where
        T: StateComponent,
    {
        // Check the cache
        if let Some(state_entry) = self.get_cache_entry_as_state(state_key) {
            return Ok(Some(state_entry));
        }

        // Retrieve the state from the DB
        let Some(state_data) = self.retrieve_state_encoded(state_key).await? else {
            return Ok(None);
        };

        let state_entry = T::decode(&mut state_data.as_slice())?;
        // Insert the entry into the cache
        self.insert_clean_cache_entry_and_snapshot(state_key, state_entry.clone());
        Ok(Some(state_entry))
    }

    async fn with_mut_state_entry_internal<T, F, E>(
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
        // Only `StateMut::Update` and `StateMut::Remove` are allowed.
        if let StateMut::Add = state_mut {
            return Err(StateManagerError::WrongStateMutType);
        }

        let state_exists = self
            .get_state_entry_internal::<T>(state_key)
            .await?
            .is_some();

        if !state_exists {
            return Err(StateManagerError::StateKeyNotInitialized(
                state_key.encode_hex(),
            ));
        }

        self.cache.with_mut_entry(state_key, state_mut, f)
    }

    async fn add_state_entry_internal<T>(
        &self,
        state_key: &StateKey,
        state_entry: T,
    ) -> Result<(), StateManagerError>
    where
        T: StateComponent,
    {
        // Ensure the state entry doesn't exist.
        let state_exists = self
            .get_state_entry_internal::<T>(state_key)
            .await?
            .is_some();
        // Note: Simple state entries should be only `Add`ed in the genesis setup.
        // Also, mutation on account-related state entries (e.g., account storage entries) are
        // gated via sandboxed partial state. Since `Add` and `Update` cases are explicitly handled
        // in service STFs after accumulation, attempting to `Add` state entries that
        // already exist returns error here.
        if state_exists {
            return Err(StateManagerError::StateEntryAlreadyExists);
        }

        let state_entry_type = Arc::new(state_entry.into_entry_type());
        self.cache.insert_entry(
            state_key.clone(),
            CacheEntry {
                clean_snapshot: state_entry_type.clone(),
                value: state_entry_type,
                status: CacheEntryStatus::Dirty(StateMut::Add),
            },
        );

        Ok(())
    }

    async fn get_clean_simple_state_entry<T>(&self) -> Result<T, StateManagerError>
    where
        T: SimpleStateComponent,
    {
        let state_key = get_simple_state_key(T::STATE_KEY_CONSTANT);
        self.get_clean_state_entry_internal(&state_key)
            .await?
            .ok_or(StateManagerError::StateKeyNotInitialized(
                state_key.encode_hex(),
            )) // simple state key must be initialized
    }

    async fn get_simple_state_entry<T>(&self) -> Result<T, StateManagerError>
    where
        T: SimpleStateComponent,
    {
        let state_key = get_simple_state_key(T::STATE_KEY_CONSTANT);
        self.get_state_entry_internal(&state_key).await?.ok_or(
            StateManagerError::StateKeyNotInitialized(state_key.encode_hex()),
        ) // simple state key must be initialized
    }

    async fn with_mut_simple_state_entry<T, F, E>(
        &self,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: SimpleStateComponent,
        F: FnOnce(&mut T) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        self.with_mut_state_entry_internal(
            &get_simple_state_key(T::STATE_KEY_CONSTANT),
            state_mut,
            f,
        )
        .await
    }

    async fn add_simple_state_entry<T>(&self, state_entry: T) -> Result<(), StateManagerError>
    where
        T: SimpleStateComponent,
    {
        self.add_state_entry_internal(&get_simple_state_key(T::STATE_KEY_CONSTANT), state_entry)
            .await
    }

    async fn get_account_state_entry<T>(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<T>, StateManagerError>
    where
        T: AccountStateComponent,
    {
        self.get_state_entry_internal(state_key).await // account state key could not be initialized yet
    }

    async fn with_mut_account_state_entry<T, F, E>(
        &self,
        state_key: &StateKey,
        state_mut: StateMut,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        T: AccountStateComponent,
        F: FnOnce(&mut T) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        self.with_mut_state_entry_internal(state_key, state_mut, f)
            .await
    }

    async fn add_account_state_entry<T>(
        &self,
        state_key: &StateKey,
        state_entry: T,
    ) -> Result<(), StateManagerError>
    where
        T: AccountStateComponent,
    {
        self.add_state_entry_internal(state_key, state_entry).await
    }

    impl_simple_state_accessors!(AuthPool, auth_pool);
    impl_simple_state_accessors!(AuthQueue, auth_queue);
    impl_simple_state_accessors!(BlockHistory, block_history);
    impl_simple_state_accessors!(SafroleState, safrole);
    impl_simple_state_accessors!(DisputesState, disputes);
    impl_simple_state_accessors!(EpochEntropy, epoch_entropy);
    impl_simple_state_accessors!(StagingSet, staging_set);
    impl_simple_state_accessors!(ActiveSet, active_set);
    impl_simple_state_accessors!(PastSet, past_set);
    impl_simple_state_accessors!(PendingReports, pending_reports);
    impl_simple_state_accessors!(Timeslot, timeslot);
    impl_simple_state_accessors!(PrivilegedServices, privileged_services);
    impl_simple_state_accessors!(OnChainStatistics, onchain_statistics);
    impl_simple_state_accessors!(AccumulateQueue, accumulate_queue);
    impl_simple_state_accessors!(AccumulateHistory, accumulate_history);
    impl_simple_state_accessors!(LastAccumulateOutputs, last_accumulate_outputs);

    pub async fn get_account_metadata(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        let state_key = get_account_metadata_state_key(service_id);
        self.get_account_state_entry(&state_key).await
    }

    pub async fn with_mut_account_metadata<F, E>(
        &self,
        state_mut: StateMut,
        service_id: ServiceId,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountMetadata) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        let state_key = get_account_metadata_state_key(service_id);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
            .await
    }

    pub async fn add_account_metadata(
        &self,
        service_id: ServiceId,
        metadata: AccountMetadata,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_metadata_state_key(service_id);
        self.add_account_state_entry(&state_key, metadata).await
    }

    pub async fn get_account_storage_entry(
        &self,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        let state_key = get_account_storage_state_key(service_id, storage_key);
        self.get_account_state_entry(&state_key).await
    }

    pub async fn with_mut_account_storage_entry<F, E>(
        &self,
        state_mut: StateMut,
        service_id: ServiceId,
        storage_key: &StorageKey,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountStorageEntry) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        let state_key = get_account_storage_state_key(service_id, storage_key);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
            .await
    }

    pub async fn add_account_storage_entry(
        &self,
        service_id: ServiceId,
        storage_key: &StorageKey,
        storage_entry: AccountStorageEntry,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_storage_state_key(service_id, storage_key);
        self.add_account_state_entry(&state_key, storage_entry)
            .await
    }

    pub async fn get_account_preimages_entry(
        &self,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        let state_key = get_account_preimage_state_key(service_id, preimages_key);
        self.get_account_state_entry(&state_key).await
    }

    pub async fn with_mut_account_preimages_entry<F, E>(
        &self,
        state_mut: StateMut,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountPreimagesEntry) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        let state_key = get_account_preimage_state_key(service_id, preimages_key);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
            .await
    }

    pub async fn add_account_preimages_entry(
        &self,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
        preimages_entry: AccountPreimagesEntry,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_preimage_state_key(service_id, preimages_key);
        self.add_account_state_entry(&state_key, preimages_entry)
            .await
    }

    pub async fn get_account_lookups_entry(
        &self,
        service_id: ServiceId,
        lookups_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let state_key = get_account_lookups_state_key(service_id, lookups_key);
        self.get_account_state_entry(&state_key).await
    }

    pub async fn with_mut_account_lookups_entry<F, E>(
        &self,
        state_mut: StateMut,
        service_id: ServiceId,
        lookups_key: LookupsKey,
        f: F,
    ) -> Result<(), StateManagerError>
    where
        F: FnOnce(&mut AccountLookupsEntry) -> Result<(), E>,
        StateManagerError: From<E>,
    {
        let state_key = get_account_lookups_state_key(service_id, &lookups_key);
        self.with_mut_account_state_entry(&state_key, state_mut, f)
            .await
    }

    pub async fn add_account_lookups_entry(
        &self,
        service_id: ServiceId,
        lookups_key: LookupsKey,
        lookups_entry: AccountLookupsEntry,
    ) -> Result<(), StateManagerError> {
        let state_key = get_account_lookups_state_key(service_id, &lookups_key);
        self.add_account_state_entry(&state_key, lookups_entry)
            .await
    }
}
