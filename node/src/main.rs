use clap::Parser;
use rjam_block::header_db::BlockHeaderDB;
use rjam_common::utils::tracing::setup_tracing;
use rjam_db::{
    config::{RocksDBOpts, HEADER_CF_NAME},
    core::core_db::CoreDB,
};
use rjam_extrinsics::pool::XtPool;
use rjam_network::endpoint::QuicEndpoint;
use rjam_node::{
    cli::{Cli, CliCommand},
    node::JamNode,
};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    // CLI args
    match Cli::parse().command {
        CliCommand::Run { dev_account } => {
            let validator_info = match &dev_account {
                Some(account) => account.load_validator_key_info(),
                None => {
                    panic!("Dev account is not set.");
                }
            };

            let socket_addr = validator_info.socket_addr_v6;
            let (header_db, state_manager, _xt_pool) = init_storage()?;
            tracing::info!("Storage initialized");

            let node = JamNode::new(
                validator_info,
                Arc::new(state_manager),
                Arc::new(header_db),
                QuicEndpoint::new(socket_addr),
            );
            tracing::info!("Node initialized: {}", node.validator_info);
        }
    };

    Ok(())
}
