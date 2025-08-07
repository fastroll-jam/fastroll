use crate::{
    cache::StateCache,
    manager::StateManager,
    state_db::StateDB,
    types::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue, BlockHistory,
        DisputesState, EpochEntropy, LastAccumulateOutputs, OnChainStatistics, PastSet,
        PendingReports, PrivilegedServices, SafroleState, StagingSet, Timeslot,
    },
};
use fr_block::{
    header_db::BlockHeaderDB, post_state_root_db::PostStateRootDB, types::block::BlockHeader,
    xt_db::XtDB,
};
use fr_db::{
    config::{
        RocksDBOpts, HEADER_CF_NAME, MERKLE_CF_NAME, POST_STATE_ROOT_CF_NAME, STATE_CF_NAME,
        XT_CF_NAME,
    },
    core::core_db::CoreDB,
};
use fr_state_merkle::merkle_db::MerkleDB;
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
    pub last_accumulate_outputs: LastAccumulateOutputs,
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
    state_manager
        .add_last_accumulate_outputs(ss.last_accumulate_outputs)
        .await?;
    Ok(())
}
