//! End-to-end state transition tests
use rjam_block::{header_db::BlockHeaderDB, types::block::Block};
use rjam_common::{utils::tracing::setup_timed_tracing, ValidatorIndex};
use rjam_conformance_tests::{
    asn_types::common::{validators_data_to_validator_set, AsnBlock, AsnValidatorsData},
    utils::AsnTypeLoader,
};
use rjam_node::actors::{author::BlockAuthor, importer::BlockImporter};
use rjam_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager, SimpleStates},
    types::ActiveSet,
};
use std::{error::Error, path::PathBuf, sync::Arc};

pub fn load_genesis_block_from_file() -> Block {
    let json_path = PathBuf::from("src/genesis-data/genesis_block.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_block: AsnBlock = AsnTypeLoader::load_from_json_file(&full_path);
    asn_block.into()
}

pub fn load_genesis_active_set_from_file() -> ActiveSet {
    let json_path = PathBuf::from("src/genesis-data/genesis_active_set.json");
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(json_path);
    let asn_active_set: AsnValidatorsData = AsnTypeLoader::load_from_json_file(&full_path);
    ActiveSet(validators_data_to_validator_set(&asn_active_set))
}

/// Mocking Author Info
fn get_author_index() -> ValidatorIndex {
    ValidatorIndex::default()
}

/// Mocking DB initialization and genesis state.
async fn init_with_genesis_state() -> Result<(Arc<BlockHeaderDB>, Arc<StateManager>), Box<dyn Error>>
{
    // Genesis header is the best header
    let genesis_header = load_genesis_block_from_file().header;
    let (header_db, state_manager) = init_db_and_manager(Some(genesis_header));
    let header_db = Arc::new(header_db);
    let state_manager = Arc::new(state_manager);

    // Init genesis simple state with `ActiveSet` value
    let genesis_simple_state = SimpleStates {
        active_set: load_genesis_active_set_from_file(),
        ..Default::default()
    };

    // Commit genesis state
    add_all_simple_state_entries(&state_manager, Some(genesis_simple_state)).await?;
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
    let (header_db, state_manager) = init_with_genesis_state().await?;
    // Get the best header of the best chain
    let best_header = header_db.get_best_header();

    // Block author actor
    let mut author = BlockAuthor::new(state_manager, best_header, get_author_index());
    let (new_block, _author_post_state_root) = author.author_block(header_db).await?;

    // --- Block importing

    // Init DB and StateManager
    let (header_db, state_manager) = init_with_genesis_state().await?;
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
