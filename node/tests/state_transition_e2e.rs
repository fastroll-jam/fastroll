//! End-to-end state transition tests
use rjam_block::header_db::BlockHeaderDB;
use rjam_common::{utils::tracing::setup_timed_tracing, ValidatorIndex};
use rjam_node::roles::author::BlockAuthor;
use rjam_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
};
use std::{error::Error, sync::Arc};

/// Mocking Author Info
fn get_author_index() -> ValidatorIndex {
    ValidatorIndex::default()
}

/// Mocking DB initialization and previous state.
///
/// This sets `parent_hash` and `parent_state_root` fields of `BlockHeader` during the initialization.
async fn init_with_prev_state() -> Result<(BlockHeaderDB, Arc<StateManager>), Box<dyn Error>> {
    let (header_db, state_manager) = init_db_and_manager();
    let state_manager = Arc::new(state_manager);
    add_all_simple_state_entries(&state_manager).await?;
    state_manager.commit_dirty_cache().await?;
    Ok((header_db, state_manager))
}

/// Mocking block author actor
#[tokio::test]
async fn block_author_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // Init DB and StateManager
    let (header_db, state_manager) = init_with_prev_state().await?;

    // Instantiate a block author
    let best_header = header_db.get_best_header();
    let mut author = BlockAuthor::new(state_manager, best_header, get_author_index());
    let new_block = author.author_block(Arc::new(header_db)).await?;
    tracing::debug!("New block authored: {:?}", new_block);

    Ok(())
}
