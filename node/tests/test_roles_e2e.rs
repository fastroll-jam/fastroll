//! End-to-end state transition tests
#![allow(dead_code, unused_imports)]
use fr_common::utils::tracing::setup_timed_tracing;
use fr_config::StorageConfig;
use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_node::{
    genesis::{genesis_simple_state, load_genesis_block},
    jam_node::JamNode,
    keystore::dev_account_profile::DevNodeAccountProfile,
    roles::{
        author::BlockAuthor,
        importer::{BlockCommitMode, BlockImporter},
    },
};
use fr_state::state_utils::add_all_simple_state_entries;
use fr_storage::node_storage::NodeStorage;
use std::{
    error::Error,
    net::{Ipv6Addr, SocketAddrV6},
    path::PathBuf,
    sync::Arc,
};
use tempfile::tempdir;

fn init_node_storage(temp_path: PathBuf) -> NodeStorage {
    NodeStorage::new(StorageConfig::from_path(temp_path)).expect("Failed to initialize NodeStorage")
}

/// Mocking DB initialization and genesis state.
async fn init_with_genesis_state(
    socket_addr_v6: SocketAddrV6,
    temp_path: PathBuf,
) -> Result<JamNode, Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block().header;
    let genesis_header_hash = genesis_header.hash()?;
    let storage = Arc::new(init_node_storage(temp_path));
    storage.header_db().set_best_header(genesis_header);
    let state_manager = storage.state_manager();
    // Init genesis simple state with initial validators: active set and pending set
    add_all_simple_state_entries(&state_manager, Some(genesis_simple_state())).await?;
    // Commit genesis state
    state_manager.commit_dirty_cache().await?;

    // Commit posterior state root of the genesis block
    let post_state_root = state_manager.merkle_root().await?;
    storage
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
    let node = JamNode::new(node_info, storage, network_manager);

    // Load initial validator peers from the genesis validator set state
    node.network_manager()
        .load_validator_peers(node.storage(), socket_addr)
        .await?;

    Ok(node)
}

/// Mocking block author role
#[cfg(feature = "tiny")]
#[tokio::test]
async fn author_importer_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // --- Block authoring

    // Init DB and StateManager
    let author_socket_addr_v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0);
    let author_node_id = author_socket_addr_v6.to_string();
    let _author_node_temp_path = tempdir().unwrap();
    let author_db_path = _author_node_temp_path
        .path()
        .join("author_node_db")
        .join(author_node_id);
    let author_node = init_with_genesis_state(author_socket_addr_v6, author_db_path).await?;

    // Block author role
    let mut author = BlockAuthor::new_for_fallback_test()?;
    let (new_block, author_post_state_root) =
        author.author_block_for_test(author_node.storage()).await?;

    // --- Block importing

    // Init DB and StateManager
    let importer_socket_addr_v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9998, 0, 0);
    let importer_node_id = importer_socket_addr_v6.to_string();
    let _importer_node_temp_path = tempdir().unwrap();
    let importer_db_path = _importer_node_temp_path
        .path()
        .join("importer_node_db")
        .join(importer_node_id);
    let importer_node = init_with_genesis_state(importer_socket_addr_v6, importer_db_path).await?;

    // Block importer role
    let output = BlockImporter::import_block(
        importer_node.storage(),
        new_block,
        false,
        BlockCommitMode::Immediate,
    )
    .await?;
    assert_eq!(author_post_state_root, output.post_state_root);

    Ok(())
}
