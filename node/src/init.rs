use crate::{
    cli::{Cli, CliCommand},
    jam_node::JamNode,
};
use clap::Parser;
use rjam_block::header_db::BlockHeaderDB;
use rjam_common::{utils::tracing::setup_tracing, ByteEncodable};
use rjam_db::{
    config::{RocksDBOpts, HEADER_CF_NAME},
    core::core_db::CoreDB,
};
use rjam_extrinsics::pool::XtPool;
use rjam_network::{endpoint::QuicEndpoint, peers::PeerManager};
use rjam_state::{config::StateManagerConfig, manager::StateManager};
use std::{error::Error, path::PathBuf, sync::Arc};

fn init_storage() -> Result<(BlockHeaderDB, StateManager, XtPool), Box<dyn Error>> {
    let core_db = Arc::new(CoreDB::open(
        PathBuf::from("./.rocksdb"),
        RocksDBOpts::default(),
    )?);
    let header_db = BlockHeaderDB::new(core_db.clone(), HEADER_CF_NAME, 1024, None);
    let state_manager = StateManager::from_core_db(core_db, StateManagerConfig::default());
    let xt_pool = XtPool::new(1024);
    Ok((header_db, state_manager, xt_pool))
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
            let (header_db, state_manager, _xt_pool) = init_storage()?;
            tracing::info!("Storage initialized");
            let state_manager = Arc::new(state_manager);
            let peer_manager = PeerManager::new(state_manager.clone()).await?;

            let node = JamNode::new(
                node_info,
                state_manager,
                Arc::new(header_db),
                Arc::new(peer_manager),
                QuicEndpoint::new(socket_addr),
            );
            tracing::info!("Node initialized\n[ValidatorInfo]\nSocket Address: {}\nBandersnatch Key: 0x{}\nEd25519 Key: 0x{}\n", node.node_info.socket_addr, node.node_info.validator_key.bandersnatch_key.to_hex(), node.node_info.validator_key.ed25519_key.to_hex());
            Ok(node)
        }
    }
}
