#![allow(dead_code)]
use crate::StateManager;
use rand::{thread_rng, Rng};
use rjam_common::{ByteArray, Hash32};
use rjam_db::{core::CoreDB, header_db::BlockHeaderDB};
use rjam_state_merkle::{merkle_db::MerkleDB, state_db::StateDB};
use rjam_types::{
    state::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue, BlockHistory,
        DisputesState, EntropyAccumulator, PastSet, PendingReports, PrivilegedServices,
        SafroleState, StagingSet, Timeslot, ValidatorStats,
    },
    state_utils::{get_simple_state_key, StateComponent, StateKeyConstant},
};
use std::{error::Error, sync::Arc};
use tempfile::tempdir;

fn init_core_db() -> CoreDB {
    let db_path = tempdir().unwrap().path().join("test_db");
    CoreDB::open(db_path, true).unwrap()
}

fn init_merkle_db(core_db: Arc<CoreDB>) -> MerkleDB {
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    MerkleDB::new(core_db, MERKLE_DB_CACHE_SIZE)
}

fn init_state_db(core_db: Arc<CoreDB>) -> StateDB {
    StateDB::new(core_db)
}

fn init_header_db(core_db: Arc<CoreDB>) -> BlockHeaderDB {
    const HEADER_DB_CACHE_SIZE: usize = 1000;
    BlockHeaderDB::new(core_db, HEADER_DB_CACHE_SIZE)
}

fn init_state_manager(core_db: Arc<CoreDB>) -> StateManager {
    let merkle_db = init_merkle_db(core_db.clone());
    let state_db = init_state_db(core_db);
    StateManager::new(state_db, merkle_db)
}

pub fn init_db_and_manager() -> (BlockHeaderDB, StateManager) {
    let core_db = Arc::new(init_core_db());
    (init_header_db(core_db.clone()), init_state_manager(core_db))
}

pub fn random_state_key() -> Hash32 {
    let mut rng = thread_rng();
    ByteArray::new(rng.gen())
}

pub fn random_state_val(max_len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let len = rng.gen_range(0..max_len);
    let mut data = vec![0u8; len];
    rng.fill(&mut data[..]);
    data
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
