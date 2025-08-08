//! End-to-end state transition tests
use fr_block::types::block::BlockHeader;
use fr_common::utils::tracing::setup_timed_tracing;
use fr_config::StorageConfig;
use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_node::{
    genesis::{genesis_simple_state, load_genesis_block_from_file},
    jam_node::JamNode,
    keystore::dev_account_profile::DevNodeAccountProfile,
    roles::{author::BlockAuthor, importer::BlockImporter},
};
use fr_state::state_utils::add_all_simple_state_entries;
use fr_storage::node_storage::NodeStorage;
use std::{
    error::Error,
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

fn init_node_storage(node_id: &str, best_header: Option<BlockHeader>) -> NodeStorage {
    NodeStorage::new(StorageConfig::from_node_id(node_id), best_header)
        .expect("Failed to initialize NodeStorage")
}

/// Mocking DB initialization and genesis state.
async fn init_with_genesis_state(socket_addr_v6: SocketAddrV6) -> Result<JamNode, Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block_from_file().header;
    let genesis_header_hash = genesis_header.hash()?;
    let node_storage = Arc::new(init_node_storage(
        socket_addr_v6.to_string().as_str(),
        Some(genesis_header),
    ));
    let state_manager = node_storage.state_manager();
    // Init genesis simple state with initial validators: active set and pending set
    add_all_simple_state_entries(&state_manager, Some(genesis_simple_state())).await?;
    // Commit genesis state
    state_manager.commit_dirty_cache().await?;

    // Commit posterior state root of the genesis block
    let post_state_root = state_manager.merkle_root();
    node_storage
        .post_state_root_db()
        .set_post_state_root(&genesis_header_hash, post_state_root)
        .await?;

    // Init network manager with dev account
    let dev_account_name = DevNodeAccountProfile::Fergie;
    let node_info = dev_account_name.load_validator_key_info();
    let socket_addr = node_info.socket_addr;
    let network_manager =
        Arc::new(NetworkManager::new(node_info.clone(), QuicEndpoint::new(socket_addr_v6)).await?);

    // Construct JamNode
    let node = JamNode::new(node_info, node_storage, network_manager);

    // Load initial validator peers from the genesis validator set state
    node.network_manager()
        .load_validator_peers(node.storage(), socket_addr)
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

    // Block author role
    let mut author = BlockAuthor::new_for_fallback_test()?;
    let (new_block, author_post_state_root) =
        author.author_block_for_test(author_node.storage()).await?;

    // --- Block importing

    // Init DB and StateManager
    let importer_node =
        init_with_genesis_state(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9998, 0, 0)).await?;

    // Block importer role
    let (importer_post_state_root, _) =
        BlockImporter::import_block(importer_node.storage(), new_block).await?;
    assert_eq!(author_post_state_root, importer_post_state_root);

    Ok(())
}
