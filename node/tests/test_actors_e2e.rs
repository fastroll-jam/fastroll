//! End-to-end state transition tests
use rjam_common::{utils::tracing::setup_timed_tracing, ByteArray, ByteEncodable};
use rjam_crypto::types::{BandersnatchPubKey, BlsPubKey, Ed25519PubKey, ValidatorKey};
use rjam_network::{endpoint::QuicEndpoint, peers::PeerManager};
use rjam_node::{
    actors::{author::BlockAuthor, importer::BlockImporter},
    genesis::{genesis_simple_state, load_genesis_block_from_file},
    jam_node::{JamNode, NodeInfo},
};
use rjam_state::test_utils::{add_all_simple_state_entries, init_db_and_manager};
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

    // Init peer manager
    let state_manager = Arc::new(state_manager);
    let peer_manager = Arc::new(PeerManager::new(state_manager.clone()).await?);

    // Dev account
    let node_info = NodeInfo {
        socket_addr: socket_addr_v6,
        validator_key: ValidatorKey {
            bandersnatch_key: BandersnatchPubKey::from_hex(
                "0xf16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d",
            )
            .unwrap(),
            ed25519_key: Ed25519PubKey::from_hex(
                "0x837ce344bc9defceb0d7de7e9e9925096768b7adb4dad932e532eb6551e0ea02",
            )
            .unwrap(),
            bls_key: BlsPubKey::default(),
            metadata: ByteArray::default(),
        },
    };

    Ok(JamNode {
        node_info,
        state_manager,
        header_db: Arc::new(header_db),
        peer_manager,
        endpoint: QuicEndpoint::new(socket_addr_v6),
    })
}

/// Mocking block author actor
#[tokio::test]
async fn author_importer_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    // --- Block authoring

    // Init DB and StateManager
    let author_node =
        init_with_genesis_state(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0)).await?;
    // Get the best header of the best chain
    let best_header = author_node.header_db.get_best_header();

    // Block author actor
    let mut author =
        BlockAuthor::new_for_fallback_test(author_node.state_manager, best_header).await?;
    let (new_block, author_post_state_root) = author.author_block(author_node.header_db).await?;

    // --- Block importing

    // Init DB and StateManager
    let importer_node =
        init_with_genesis_state(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9998, 0, 0)).await?;
    // Get the best header of the best chain
    let best_header = importer_node.header_db.get_best_header();

    // Block importer actor
    let mut importer = BlockImporter::new(
        importer_node.state_manager,
        importer_node.header_db,
        Some(best_header),
    );
    importer.import_block(new_block).await?;
    let importer_post_state_root = importer.validate_block().await?;
    assert_eq!(author_post_state_root, importer_post_state_root);

    Ok(())
}
