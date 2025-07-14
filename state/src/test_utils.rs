use crate::{
    cache::StateCache,
    manager::StateManager,
    state_db::StateDB,
    state_utils::{get_simple_state_key, StateComponent, StateKeyConstant},
    types::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue, BlockHistory,
        DisputesState, EpochEntropy, OnChainStatistics, PastSet, PendingReports,
        PrivilegedServices, SafroleState, StagingSet, Timeslot,
    },
};
use fr_block::{
    header_db::BlockHeaderDB, post_state_root_db::PostStateRootDB, types::block::BlockHeader,
    xt_db::XtDB,
};
use fr_common::StateKey;
use fr_db::{
    config::{
        RocksDBOpts, HEADER_CF_NAME, MERKLE_CF_NAME, POST_STATE_ROOT_CF_NAME, STATE_CF_NAME,
        XT_CF_NAME,
    },
    core::core_db::CoreDB,
};
use fr_state_merkle::merkle_db::MerkleDB;
use rand::{thread_rng, Rng};
use std::{error::Error, sync::Arc};
use tempfile::tempdir;

fn init_core_db() -> CoreDB {
    let db_path = tempdir().unwrap().path().join("test_db");
    CoreDB::open(db_path, RocksDBOpts::default()).unwrap()
}

fn init_merkle_db(core_db: Arc<CoreDB>) -> MerkleDB {
    const MERKLE_DB_CACHE_SIZE: usize = 1024;
    MerkleDB::new(core_db, MERKLE_CF_NAME, MERKLE_DB_CACHE_SIZE)
}

fn init_state_db(core_db: Arc<CoreDB>) -> StateDB {
    const STATE_DB_CACHE_SIZE: usize = 1024;
    StateDB::new(core_db, STATE_CF_NAME, STATE_DB_CACHE_SIZE)
}

fn init_state_cache() -> StateCache {
    const STATE_CACHE_SIZE: usize = 4096;
    StateCache::new(STATE_CACHE_SIZE)
}

fn init_header_db(core_db: Arc<CoreDB>, best_header: Option<BlockHeader>) -> BlockHeaderDB {
    const HEADER_DB_CACHE_SIZE: usize = 1024;
    BlockHeaderDB::new(core_db, HEADER_CF_NAME, HEADER_DB_CACHE_SIZE, best_header)
}

fn init_xt_db(core_db: Arc<CoreDB>) -> XtDB {
    const XT_DB_CACHE_SIZE: usize = 1024;
    XtDB::new(core_db, XT_CF_NAME, XT_DB_CACHE_SIZE)
}

fn init_state_manager(core_db: Arc<CoreDB>) -> StateManager {
    let merkle_db = init_merkle_db(core_db.clone());
    let state_db = init_state_db(core_db);

    StateManager::new(state_db, merkle_db, init_state_cache())
}

fn init_post_state_root_db(core_db: Arc<CoreDB>) -> PostStateRootDB {
    const STATE_DB_CACHE_SIZE: usize = 1024;
    PostStateRootDB::new(core_db, POST_STATE_ROOT_CF_NAME, STATE_DB_CACHE_SIZE)
}

pub fn init_db_and_manager(
    best_header: Option<BlockHeader>,
) -> (BlockHeaderDB, XtDB, StateManager, PostStateRootDB) {
    let core_db = Arc::new(init_core_db());
    (
        init_header_db(core_db.clone(), best_header),
        init_xt_db(core_db.clone()),
        init_state_manager(core_db.clone()),
        init_post_state_root_db(core_db),
    )
}

pub fn random_state_key() -> StateKey {
    let mut rng = thread_rng();
    StateKey::new(rng.gen())
}

pub fn random_state_val(max_len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let len = rng.gen_range(max_len / 2..max_len);
    let mut data = vec![0u8; len];
    rng.fill(&mut data[..]);
    data
}

/// Note: test-only
#[derive(Default)]
pub struct SimpleStates {
    pub auth_pool: AuthPool,
    pub auth_queue: AuthQueue,
    pub block_history: BlockHistory,
    pub safrole: SafroleState,
    pub disputes: DisputesState,
    pub entropy: EpochEntropy,
    pub staging_set: StagingSet,
    pub active_set: ActiveSet,
    pub past_set: PastSet,
    pub reports: PendingReports,
    pub timeslot: Timeslot,
    pub privileges: PrivilegedServices,
    pub onchain_statistics: OnChainStatistics,
    pub accumulate_queue: AccumulateQueue,
    pub accumulate_history: AccumulateHistory,
}

pub async fn add_all_simple_state_entries(
    state_manager: &StateManager,
    test_simple_states: Option<SimpleStates>,
) -> Result<(), Box<dyn Error>> {
    let ss = test_simple_states.unwrap_or_default();
    state_manager.add_auth_pool(ss.auth_pool).await?;
    state_manager.add_auth_queue(ss.auth_queue).await?;
    state_manager.add_block_history(ss.block_history).await?;
    state_manager.add_safrole(ss.safrole).await?;
    state_manager.add_disputes(ss.disputes).await?;
    state_manager.add_epoch_entropy(ss.entropy).await?;
    state_manager.add_staging_set(ss.staging_set).await?;
    state_manager.add_active_set(ss.active_set).await?;
    state_manager.add_past_set(ss.past_set).await?;
    state_manager.add_pending_reports(ss.reports).await?;
    state_manager.add_timeslot(ss.timeslot).await?;
    state_manager.add_privileged_services(ss.privileges).await?;
    state_manager
        .add_onchain_statistics(ss.onchain_statistics)
        .await?;
    state_manager
        .add_accumulate_queue(ss.accumulate_queue)
        .await?;
    state_manager
        .add_accumulate_history(ss.accumulate_history)
        .await?;
    Ok(())
}

pub async fn compare_all_simple_state_cache_and_db(
    state_manager: &StateManager,
) -> Result<(), Box<dyn Error>> {
    assert!(
        compare_cache_and_db::<AuthPool>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::AuthPool)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<AuthQueue>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::AuthQueue)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<BlockHistory>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::BlockHistory)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<SafroleState>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::SafroleState)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<DisputesState>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::DisputesState)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<EpochEntropy>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::EpochEntropy)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<StagingSet>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::StagingSet)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<ActiveSet>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::ActiveSet)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<PastSet>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::PastSet)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<PendingReports>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::PendingReports)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<Timeslot>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::Timeslot)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<PrivilegedServices>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::PrivilegedServices)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<OnChainStatistics>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::OnChainStatistics)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<AccumulateQueue>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::AccumulateQueue)
        )
        .await?
    );
    assert!(
        compare_cache_and_db::<AccumulateHistory>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::AccumulateHistory)
        )
        .await?
    );

    Ok(())
}

pub async fn compare_cache_and_db<T: StateComponent>(
    state_manager: &StateManager,
    state_key: &StateKey,
) -> Result<bool, Box<dyn Error>> {
    let db_entry_encoded = state_manager
        .retrieve_state_encoded(state_key)
        .await?
        .unwrap();
    let db_entry = T::decode(&mut db_entry_encoded.as_slice())?;
    let cache_entry = state_manager.get_cache_entry_as_state(state_key).unwrap();
    Ok(db_entry == cache_entry)
}
