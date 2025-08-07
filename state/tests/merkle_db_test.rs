//! MerkleDB Integration Tests
use fr_codec::prelude::*;
use fr_common::{utils::tracing::setup_timed_tracing, Hash32, StateKey};
use fr_crypto::{hash, Blake2b256};
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    state_utils::{get_simple_state_key, StateComponent, StateKeyConstant},
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
    types::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, AuthQueue, BlockHistory,
        DisputesState, EpochEntropy, LastAccumulateOutputs, OnChainStatistics, PastSet,
        PendingReport, PendingReports, PrivilegedServices, SafroleState, StagingSet, Timeslot,
    },
};
use std::error::Error;

fn hash_str(value: &str) -> Hash32 {
    hash::<Blake2b256>(value.as_bytes()).unwrap()
}

async fn compare_cache_and_db<T: StateComponent>(
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
    assert!(
        compare_cache_and_db::<LastAccumulateOutputs>(
            state_manager,
            &get_simple_state_key(StateKeyConstant::LastAccumulateOutputs)
        )
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn merkle_db_test() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    let (_, _, state_manager, _) = init_db_and_manager(None);

    // --- 1. Add one state entry, initializing the Merkle Trie
    tracing::info!("1. Add the first state entry.");
    let mut auth_pool = AuthPool::default();
    auth_pool.0[0].try_push(hash_str("00")).unwrap();
    auth_pool.0[1].try_push(hash_str("01")).unwrap();
    let auth_pool_expected = auth_pool.clone();

    // Apply state mutation
    state_manager.add_auth_pool(auth_pool).await?;

    // Commit to the DB
    let auth_pool_state_key = get_simple_state_key(StateKeyConstant::AuthPool);
    state_manager
        .commit_single_dirty_cache(&auth_pool_state_key)
        .await?;
    tracing::info!(
        "--- DB Commit Done. Merkle Root: {}",
        state_manager.merkle_root()
    );

    // Retrieve the entry from the DB (not gating the state cache)
    let auth_pool_state_data = state_manager
        .retrieve_state_encoded(&auth_pool_state_key)
        .await?
        .unwrap();
    let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice())?;
    tracing::debug!("\nState Retrieved: {}", &auth_pool);
    assert_eq!(&auth_pool, &auth_pool_expected);

    // --- 2. Add another state entry
    tracing::info!("2. Add another state entry.");
    let mut pending_reports = PendingReports::default();
    pending_reports.0[0] = Some(PendingReport::default());
    pending_reports.0[1] = Some(PendingReport::default());
    let pending_reports_expected = pending_reports.clone();

    state_manager.add_pending_reports(pending_reports).await?;

    // Commit to the DB
    let pending_reports_state_key = get_simple_state_key(StateKeyConstant::PendingReports);
    state_manager
        .commit_single_dirty_cache(&pending_reports_state_key)
        .await?;
    tracing::info!(
        "--- DB Commit Done. Merkle Root: {}",
        state_manager.merkle_root()
    );

    // Retrieve the entry from the DB (not gating the state cache)
    let auth_pool_state_data = state_manager
        .retrieve_state_encoded(&auth_pool_state_key)
        .await?
        .unwrap();
    let pending_reports_state_data = state_manager
        .retrieve_state_encoded(&pending_reports_state_key)
        .await?
        .unwrap();

    let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice())?;
    let pending_reports = PendingReports::decode(&mut pending_reports_state_data.as_slice())?;

    tracing::debug!("\nState Retrieved: {}", &auth_pool);
    tracing::debug!("\nState Retrieved: {}", &pending_reports);
    assert_eq!(&auth_pool, &auth_pool_expected);
    assert_eq!(&pending_reports, &pending_reports_expected);

    // --- 3. Update state entry
    tracing::info!("3. Update state entry.");
    state_manager
        .with_mut_auth_pool(StateMut::Update, |pool| -> Result<(), StateManagerError> {
            pool.0[1].try_push(hash_str("02")).unwrap();
            Ok(())
        })
        .await?;
    let auth_pool_expected = state_manager.get_auth_pool().await?;
    state_manager
        .commit_single_dirty_cache(&auth_pool_state_key)
        .await?;
    tracing::info!(
        "--- DB Commit Done. Merkle Root: {}",
        state_manager.merkle_root()
    );

    let auth_pool_state_data = state_manager
        .retrieve_state_encoded(&auth_pool_state_key)
        .await?
        .unwrap();
    let auth_pool = AuthPool::decode(&mut auth_pool_state_data.as_slice())?;
    tracing::debug!("\nState Retrieved: {}", &auth_pool);
    assert_eq!(&auth_pool, &auth_pool_expected);

    // --- 4. Remove state entry
    tracing::info!("4. Remove state entry.");
    state_manager
        .with_mut_auth_pool(StateMut::Remove, |_| -> Result<(), StateManagerError> {
            Ok(())
        })
        .await?;
    state_manager
        .commit_single_dirty_cache(&auth_pool_state_key)
        .await?;
    tracing::info!(
        "--- DB Commit Done. Merkle Root: {}",
        state_manager.merkle_root()
    );
    // Retrieval of a removed entry must return `None`
    let auth_pool_state_data_result = state_manager
        .retrieve_state_encoded(&auth_pool_state_key)
        .await?;
    assert!(auth_pool_state_data_result.is_none());

    // Check `PendingReports` state entry is still available
    let pending_reports_state_data = state_manager
        .retrieve_state_encoded(&pending_reports_state_key)
        .await?
        .unwrap();
    let pending_reports = PendingReports::decode(&mut pending_reports_state_data.as_slice())?;
    assert_eq!(&pending_reports, &pending_reports_expected);

    Ok(())
}

#[tokio::test]
async fn merkle_db_simple_states() -> Result<(), Box<dyn Error>> {
    let (_, _, state_manager, _) = init_db_and_manager(None);
    add_all_simple_state_entries(&state_manager, None).await?;
    state_manager.commit_dirty_cache().await?;
    compare_all_simple_state_cache_and_db(&state_manager).await?;

    Ok(())
}
