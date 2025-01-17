use crate::StateManager;
use rjam_common::Hash32;
use rjam_db::RocksDBConfig;
use rjam_state_merkle::{merkle_db::MerkleDB, state_db::StateDB};
use rjam_types::{
    state::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue, BlockHistory,
        DisputesState, EntropyAccumulator, PastSet, PendingReports, PrivilegedServices,
        SafroleState, StagingSet, Timeslot, ValidatorStats,
    },
    state_utils::{get_simple_state_key, StateComponent, StateKeyConstant},
};
use std::error::Error;
use tempfile::tempdir;

pub fn init_merkle_db() -> MerkleDB {
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    MerkleDB::open(
        &RocksDBConfig::from_path(tempdir().unwrap().into_path().join("merkle_db")),
        MERKLE_DB_CACHE_SIZE,
    )
    .unwrap()
}

pub fn init_state_db() -> StateDB {
    StateDB::open(&RocksDBConfig::from_path(
        tempdir().unwrap().into_path().join("state_db"),
    ))
    .unwrap()
}

pub fn init_state_manager(state_db: StateDB, merkle_db: MerkleDB) -> StateManager {
    StateManager::new(state_db, merkle_db)
}

pub fn add_all_simple_state_entries(state_manager: &StateManager) -> Result<(), Box<dyn Error>> {
    let auth_pool = AuthPool::default();
    let auth_queue = AuthQueue::default();
    let block_history = BlockHistory::default();
    let safrole = SafroleState::default();
    let disputes = DisputesState::default();
    let entropy = EntropyAccumulator::default();
    let staging_set = StagingSet::default();
    let active_set = ActiveSet::default();
    let past_set = PastSet::default();
    let reports = PendingReports::default();
    let timeslot = Timeslot::default();
    let privileges = PrivilegedServices::default();
    let validator_stats = ValidatorStats::default();
    let accumulate_queue = AccumulateQueue::default();
    let accumulate_history = AccumulateHistory::default();

    state_manager.add_auth_pool(auth_pool)?;
    state_manager.add_auth_queue(auth_queue)?;
    state_manager.add_block_history(block_history)?;
    state_manager.add_safrole(safrole)?;
    state_manager.add_disputes(disputes)?;
    state_manager.add_entropy_accumulator(entropy)?;
    state_manager.add_staging_set(staging_set)?;
    state_manager.add_active_set(active_set)?;
    state_manager.add_past_set(past_set)?;
    state_manager.add_pending_reports(reports)?;
    state_manager.add_timeslot(timeslot)?;
    state_manager.add_privileged_services(privileges)?;
    state_manager.add_validator_stats(validator_stats)?;
    state_manager.add_accumulate_queue(accumulate_queue)?;
    state_manager.add_accumulate_history(accumulate_history)?;

    Ok(())
}

// TODO: Use batch commit instead
pub fn commit_all_simple_state_entries(state_manager: &StateManager) -> Result<(), Box<dyn Error>> {
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::AuthPool))?;
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::AuthQueue))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::BlockHistory))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::SafroleState))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::DisputesState))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::EntropyAccumulator))?;
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::StagingSet))?;
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::ActiveSet))?;
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::PastSet))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::PendingReports))?;
    state_manager.commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::Timeslot))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::PrivilegedServices))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::ValidatorStats))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::AccumulateQueue))?;
    state_manager
        .commit_single_dirty_cache(&get_simple_state_key(StateKeyConstant::AccumulateHistory))?;

    Ok(())
}

pub fn compare_all_simple_state_cache_and_db(
    state_manager: &StateManager,
) -> Result<(), Box<dyn Error>> {
    assert!(compare_cache_and_db::<AuthPool>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::AuthPool)
    )?);
    assert!(compare_cache_and_db::<AuthQueue>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::AuthQueue)
    )?);
    assert!(compare_cache_and_db::<BlockHistory>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::BlockHistory)
    )?);
    assert!(compare_cache_and_db::<SafroleState>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::SafroleState)
    )?);
    assert!(compare_cache_and_db::<DisputesState>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::DisputesState)
    )?);
    assert!(compare_cache_and_db::<EntropyAccumulator>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::EntropyAccumulator)
    )?);
    assert!(compare_cache_and_db::<StagingSet>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::StagingSet)
    )?);
    assert!(compare_cache_and_db::<ActiveSet>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::ActiveSet)
    )?);
    assert!(compare_cache_and_db::<PastSet>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::PastSet)
    )?);
    assert!(compare_cache_and_db::<PendingReports>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::PendingReports)
    )?);
    assert!(compare_cache_and_db::<Timeslot>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::Timeslot)
    )?);
    assert!(compare_cache_and_db::<PrivilegedServices>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::PrivilegedServices)
    )?);
    assert!(compare_cache_and_db::<ValidatorStats>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::ValidatorStats)
    )?);
    assert!(compare_cache_and_db::<AccumulateQueue>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::AccumulateQueue)
    )?);
    assert!(compare_cache_and_db::<AccumulateHistory>(
        state_manager,
        &get_simple_state_key(StateKeyConstant::AccumulateHistory)
    )?);

    Ok(())
}

pub fn compare_cache_and_db<T: StateComponent>(
    state_manager: &StateManager,
    state_key: &Hash32,
) -> Result<bool, Box<dyn Error>> {
    let db_entry_encoded = state_manager.retrieve_state_encoded(state_key)?.unwrap();
    let db_entry = T::decode(&mut db_entry_encoded.as_slice())?;
    let cache_entry = state_manager.get_cache_entry(state_key)?.unwrap();
    Ok(db_entry == cache_entry)
}
