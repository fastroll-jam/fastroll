//! End-to-end state transition tests
use fr_common::utils::tracing::setup_timed_tracing;
use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_node::{
    cli::DevAccountName,
    genesis::{genesis_simple_state, load_genesis_block_from_file},
    jam_node::JamNode,
    roles::{author::BlockAuthor, importer::BlockImporter},
};
use fr_state::test_utils::{add_all_simple_state_entries, init_db_and_manager};
use fr_storage::NodeStorage;
use std::{
    error::Error,
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

/// Mocking DB initialization and genesis state.
async fn init_with_genesis_state(socket_addr_v6: SocketAddrV6) -> Result<JamNode, Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block_from_file().header;
    let (header_db, state_manager) = init_db_and_manager(Some(genesis_header));

    // Init genesis simple state with initial validators: active set and pending set
    add_all_simple_state_entries(&state_manager, Some(genesis_simple_state())).await?;
    // Commit genesis state
    state_manager.commit_dirty_cache().await?;

    // Init network manager with dev account
    let dev_account_name = DevAccountName::Fergie;
    let node_info = dev_account_name.load_validator_key_info();
    let socket_addr = node_info.socket_addr;
    let network_manager =
        Arc::new(NetworkManager::new(node_info.clone(), QuicEndpoint::new(socket_addr_v6)).await?);

    // Construct JamNode
    let node_storage = Arc::new(NodeStorage::new(
        Arc::new(state_manager),
        Arc::new(header_db),
    ));

    let node = JamNode::new(node_info, node_storage, network_manager);

    // Load initial validator peers from the genesis validator set state
    node.network_manager()
        .load_validator_peers(node.storage().state_manager(), socket_addr)
        .await?;

    Ok(node)
}

/// Mocking block author role
#[tokio::test]
async fn author_importer_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // --- Block authoring

    // Init DB and StateManager
    let author_node =
        init_with_genesis_state(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0)).await?;
    // Get the best header of the best chain
    let best_header = author_node.storage().header_db().get_best_header();

    // Block author role
    let mut author =
        BlockAuthor::new_for_fallback_test(author_node.storage().state_manager(), best_header)?;
    let (new_block, author_post_state_root) = author
        .author_block_for_test(author_node.storage().header_db())
        .await?;

    // --- Block importing

    // Init DB and StateManager
    let importer_node =
        init_with_genesis_state(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9998, 0, 0)).await?;
    // Get the best header of the best chain
    let best_header = importer_node.storage().header_db().get_best_header();

    // Block importer role
    let mut importer = BlockImporter::new(importer_node.storage(), Some(best_header));
    importer.import_block(new_block).await?;
    let importer_post_state_root = importer.validate_block().await?;
    assert_eq!(author_post_state_root, importer_post_state_root);

    Ok(())
}
