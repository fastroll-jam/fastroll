//! MerkleDB Integration Tests
use rjam_codec::prelude::*;
use rjam_common::utils::tracing::setup_timed_tracing;
use rjam_state::{
    cache::StateMut,
    state_utils::{get_simple_state_key, StateKeyConstant},
    test_utils::{
        add_all_simple_state_entries, compare_all_simple_state_cache_and_db, init_db_and_manager,
    },
    types::{AuthPool, PendingReport, PendingReports},
};
use rjam_state_merkle::test_utils::simple_hash;
use std::error::Error;

#[tokio::test]
async fn merkle_db_test() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    let (_, state_manager) = init_db_and_manager();

    // --- 1. Add one state entry, initializing the Merkle Trie
    tracing::info!("1. Add the first state entry.");
    let mut auth_pool = AuthPool::default();
    auth_pool.0[0].push(simple_hash("00"));
    auth_pool.0[1].push(simple_hash("01"));
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
        .with_mut_auth_pool(StateMut::Update, |pool| {
            pool.0[1].push(simple_hash("02"));
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
        .with_mut_auth_pool(StateMut::Remove, |_| {})
        .await?;
    state_manager
        .commit_single_dirty_cache(&auth_pool_state_key)
        .await?;
    // FIXME: When there is the only state entry in the merkle trie, the leaf must be promoted to the root.
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
    let (_, state_manager) = init_db_and_manager();
    add_all_simple_state_entries(&state_manager).await?;
    state_manager.commit_dirty_cache().await?;
    compare_all_simple_state_cache_and_db(&state_manager).await?;

    Ok(())
}
