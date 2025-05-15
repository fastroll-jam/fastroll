use crate::{
    cli::{Cli, CliCommand},
    genesis::{genesis_simple_state, load_genesis_block_from_file},
    jam_node::JamNode,
    roles::manager::RoleManager,
};
use clap::Parser;
use fr_block::header_db::BlockHeaderDB;
use fr_common::{utils::tracing::setup_tracing, ByteEncodable};
use fr_db::{
    config::{RocksDBOpts, HEADER_CF_NAME},
    core::core_db::CoreDB,
};
use fr_extrinsics::pool::XtPool;
use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_state::{
    config::StateManagerConfig, manager::StateManager, test_utils::add_all_simple_state_entries,
};
use std::{error::Error, path::PathBuf, sync::Arc};

fn init_storage(db_id: &str) -> Result<(BlockHeaderDB, StateManager, XtPool), Box<dyn Error>> {
    let core_db = Arc::new(CoreDB::open(
        PathBuf::from(format!("./.rocksdb/{db_id}")),
        RocksDBOpts::default(),
    )?);
    let header_db = BlockHeaderDB::new(core_db.clone(), HEADER_CF_NAME, 1024, None);
    let state_manager = StateManager::from_core_db(core_db, StateManagerConfig::default());
    let xt_pool = XtPool::new(1024);
    Ok((header_db, state_manager, xt_pool))
}

async fn set_genesis_state(jam_node: &JamNode) -> Result<(), Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block_from_file().header;
    jam_node.header_db.set_best_header(genesis_header);
    // Init genesis simple state with initial validators: active set and pending set
    add_all_simple_state_entries(&jam_node.state_manager, Some(genesis_simple_state())).await?;
    // Commit genesis state
    jam_node.state_manager.commit_dirty_cache().await?;
    Ok(())
}

pub async fn init_node() -> Result<JamNode, Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    // CLI args
    match Cli::parse().command {
        CliCommand::Run { dev_account } => {
            let node_info = match &dev_account {
                Some(account) => account.load_validator_key_info(),
                None => {
                    panic!("Dev account is not set.");
                }
            };

            let socket_addr = node_info.socket_addr;
            let (header_db, state_manager, _xt_pool) =
                init_storage(format!("[{}]:{}", socket_addr.ip(), socket_addr.port()).as_str())?;
            tracing::info!("Storage initialized");
            let network_manager =
                NetworkManager::new(node_info.clone(), QuicEndpoint::new(socket_addr)).await?;

            let state_manager = Arc::new(state_manager);
            let role_manager = RoleManager::new(node_info, state_manager.clone());
            let node = JamNode::new(
                state_manager.clone(),
                Arc::new(header_db),
                Arc::new(network_manager),
                Arc::new(role_manager),
            );
            tracing::info!("Node initialized\n[ValidatorInfo]\nSocket Address: {}\nBandersnatch Key: 0x{}\nEd25519 Key: 0x{}\n", node.network_manager.local_node_info.socket_addr, node.network_manager.local_node_info.validator_key.bandersnatch_key.to_hex(), node.network_manager.local_node_info.validator_key.ed25519_key.to_hex());
            set_genesis_state(&node).await?;
            tracing::info!("Genesis state set");
            // Load initial validator peers from the genesis validator set state
            node.network_manager
                .load_validator_peers(state_manager, socket_addr)
                .await?;
            tracing::info!("Validator peers info loaded");
            Ok(node)
        }
    }
}
