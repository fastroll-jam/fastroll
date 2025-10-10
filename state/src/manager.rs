#![allow(dead_code)]
use crate::{
    cache::{CacheEntry, CacheEntryStatus, StateCache, StateMut},
    error::StateManagerError,
    merkle_interface::{
        actor::{MerkleActor, MerkleCommand, MerkleManagerHandle},
        manager::MerkleManager,
    },
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
    CodeHash, EpochIndex, LookupsKey, MerkleRoot, Octets, PreimagesKey, ServiceId, StateKey,
    StorageKey, TimeslotIndex, MIN_PUBLIC_SERVICE_ID,
};
use fr_config::StorageConfig;
use fr_crypto::vrf::bandersnatch_vrf::RingVrfVerifier;
use fr_db::{
    core::{
        cached_db::{CacheItem, DBKey},
        core_db::CoreDB,
    },
    WriteBatch,
};
use fr_state_merkle_v2::{merkle_db::MerkleDB, types::LeafNodeData};
use std::{
    future::Future,
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;
use tracing::instrument;

pub struct StateManager {
    state_db: StateDB,
    cache: StateCache,
    merkle_manager: MerkleManagerHandle,
    ring_vrf_verifier_cache: RwLock<Option<(EpochIndex, RingVrfVerifier)>>,
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
                core_db.clone(),
                cfg.cfs.merkle_nodes_db.cf_name,
                cfg.cfs.merkle_leaf_paths_db.cf_name,
                cfg.cfs.merkle_nodes_db.cache_size,
                cfg.cfs.merkle_leaf_paths_db.cache_size,
            ),
            StateCache::new(cfg.state_cache_size),
        )
    }

    pub fn new(state_db: StateDB, merkle_db: MerkleDB, cache: StateCache) -> Self {
        // Open a mpsc channel to be used for communication between StateManager and MerkleActor.
        const CHANNEL_SIZE: usize = 10;
        let (merkle_mpsc_send, merkle_mpsc_recv) = mpsc::channel::<MerkleCommand>(CHANNEL_SIZE);
        let merkle_actor = MerkleActor::new(MerkleManager::new(merkle_db), merkle_mpsc_recv);

        tokio::spawn(merkle_actor.run());

        Self {
            state_db,
            cache,
            merkle_manager: MerkleManagerHandle {
                sender: merkle_mpsc_send,
            },
            ring_vrf_verifier_cache: RwLock::new(None),
        }
    }

    pub async fn get_or_generate_ring_vrf_verifier(
        &self,
    ) -> Result<RingVrfVerifier, StateManagerError> {
        let curr_epoch_index = self.get_timeslot().await?.epoch();
        // Check the cache
        if let Some((epoch_index, verifier)) = self.ring_vrf_verifier_cache.read().unwrap().as_ref()
        {
            if *epoch_index == curr_epoch_index {
                return Ok(verifier.clone());
            }
        }
        // Generate `RingVrfVerifier` with the current pending set (γP′) and cache it to the `StateManager`
        let curr_pending_set = self.get_safrole().await?.pending_set;
        let verifier = RingVrfVerifier::new(&curr_pending_set)?;
        self.update_ring_vrf_verifier_cache(verifier.clone())
            .await?;
        Ok(verifier)
    }

    pub async fn update_ring_vrf_verifier_cache(
        &self,
        verifier: RingVrfVerifier,
    ) -> Result<(), StateManagerError> {
        let curr_epoch_index = self.get_timeslot().await?.epoch();
        self.ring_vrf_verifier_cache
            .write()
            .unwrap()
            .replace((curr_epoch_index, verifier));
        Ok(())
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
            return Err(StateManagerError::StateEntryAlreadyExists(hex::encode(
                state_key,
            )));
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

    // Note: test-only
    pub fn clear_state_cache(&self) {
        self.cache.invalidate_all();
    }

    pub async fn merkle_root(&self) -> Result<MerkleRoot, StateManagerError> {
        self.merkle_manager.get_merkle_root().await
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
            let s = MIN_PUBLIC_SERVICE_ID as u64;
            check_id = ((check_id as u64 - s + 1) % ((1 << 32) - (1 << 8) - s) + s) as ServiceId;
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
    /// Used by `accumulate` PVM invocation where direct access to on-chain state is possible.
    pub async fn get_account_code(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountCode>, StateManagerError> {
        let Some(metadata) = self.get_account_metadata(service_id).await? else {
            tracing::warn!("Account not found. s={service_id}");
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
        let leaf_node_data = match self
            .merkle_manager
            .retrieve_state(state_key.clone())
            .await?
        {
            Some(retrieved) => retrieved,
            None => return Ok(None),
        };

        let state_encoded = match leaf_node_data {
            LeafNodeData::Embedded(data) => data,
            LeafNodeData::Regular(data_hash) => {
                let Some(entry) = self.state_db.get_entry(&data_hash).await? else {
                    return Ok(None);
                };
                entry
            }
        };

        Ok(Some(state_encoded))
    }

    /// Collects all dirty cache entries after state transition, then directly commit them into
    /// `MerkleDB` and `StateDB` as a single synchronous batch write operation.
    /// After committing to the databases, marks the committed cache entries as clean.
    #[instrument(level = "debug", skip(self), name = "commit_cache")]
    pub async fn commit_dirty_cache(&self) -> Result<(), StateManagerError> {
        let dirty_entries = self.cache.collect_dirty();
        tracing::debug!("committing {} dirty cache entries", dirty_entries.len());
        if dirty_entries.is_empty() {
            return Ok(());
        }

        // Commit to StateDB
        let state_db_writes = self
            .merkle_manager
            .commit_dirty_cache(dirty_entries.clone())
            .await?;
        let mut state_db_write_batch = WriteBatch::default();
        let state_db_cf = self.state_db.cf_handle()?;
        for (k, v) in state_db_writes {
            state_db_write_batch.put_cf(state_db_cf, k.as_db_key(), v.into_db_value()?);
        }
        self.commit_to_state_db(state_db_write_batch).await?;

        // Sync up the state cache with the global state.
        self.cache.sync_cache_status(&dirty_entries);

        Ok(())
    }

    async fn commit_to_state_db(&self, batch: WriteBatch) -> Result<(), StateManagerError> {
        self.state_db.commit_write_batch(batch).await?;
        Ok(())
    }

    /// Rolls back all uncommitted state changes.
    ///
    /// This method should be called by the block processor when a block fails validation.
    /// It reverts the state cache to its last known clean state, discarding the pending state changes.
    pub fn rollback_dirty_cache(&self) {
        self.cache.rollback_dirty_cache()
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
            return Err(StateManagerError::StateEntryAlreadyExists(hex::encode(
                state_key,
            )));
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

    async fn get_clean_account_state_entry<T>(
        &self,
        state_key: &StateKey,
    ) -> Result<Option<T>, StateManagerError>
    where
        T: AccountStateComponent,
    {
        self.get_clean_state_entry_internal(state_key).await // account state key could not be initialized yet
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

    pub async fn get_account_storage_entry_clean(
        &self,
        service_id: ServiceId,
        storage_key: &StorageKey,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        let state_key = get_account_storage_state_key(service_id, storage_key);
        self.get_clean_account_state_entry(&state_key).await
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

    pub async fn get_account_preimages_entry_clean(
        &self,
        service_id: ServiceId,
        preimages_key: &PreimagesKey,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        let state_key = get_account_preimage_state_key(service_id, preimages_key);
        self.get_clean_account_state_entry(&state_key).await
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

    pub async fn get_account_lookups_entry_clean(
        &self,
        service_id: ServiceId,
        lookups_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        let state_key = get_account_lookups_state_key(service_id, lookups_key);
        self.get_clean_account_state_entry(&state_key).await
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
