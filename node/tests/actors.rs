//! End-to-end state transition tests
use rjam_block::header_db::BlockHeaderDB;
use rjam_common::{utils::tracing::setup_timed_tracing, ValidatorIndex};
use rjam_node::actors::{author::BlockAuthor, importer::BlockImporter};
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
async fn init_with_prev_state() -> Result<(Arc<BlockHeaderDB>, Arc<StateManager>), Box<dyn Error>> {
    let (header_db, state_manager) = init_db_and_manager();
    let header_db = Arc::new(header_db);
    let state_manager = Arc::new(state_manager);
    add_all_simple_state_entries(&state_manager).await?;
    state_manager.commit_dirty_cache().await?;
    Ok((header_db, state_manager))
}

/// Mocking block author actor
#[tokio::test]
async fn author_importer_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // --- Block authoring

    // Init DB and StateManager
    let (header_db, state_manager) = init_with_prev_state().await?;
    // Get the best header of the best chain
    let best_header = header_db.get_best_header();

    // Block author actor
    let mut author = BlockAuthor::new(state_manager, best_header, get_author_index());
    let (new_block, _author_post_state_root) = author.author_block(header_db).await?;

    // --- Block importing

    // Init DB and StateManager
    let (header_db, state_manager) = init_with_prev_state().await?;
    // Get the best header of the best chain
    let best_header = header_db.get_best_header();

    // Block importer actor
    let mut importer = BlockImporter::new(state_manager, header_db, Some(best_header));
    importer.import_block(new_block).await?;
    // FIXME: Load proper genesis state
    // let importer_post_state_root = importer.validate_block().await?;
    // assert_eq!(author_post_state_root, importer_post_state_root);

    Ok(())
}
