use crate::{
    genesis::{genesis_simple_state, load_genesis_block_from_file},
    jam_node::JamNode,
    keystore::dev_account_profile::DevNodeAccountProfile,
};
use fr_block::{
    header_db::BlockHeaderDB, post_state_root_db::PostStateRootDB, types::extrinsics::Extrinsics,
    xt_db::XtDB,
};
use fr_common::{ByteEncodable, Hash32};
use fr_db::{
    config::{RocksDBOpts, HEADER_CF_NAME, POST_STATE_ROOT_CF_NAME, XT_CF_NAME},
    core::core_db::CoreDB,
};
use fr_extrinsics::pool::XtPool;
use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_state::{
    config::StateManagerConfig, manager::StateManager, state_utils::add_all_simple_state_entries,
};
use fr_storage::node_storage::NodeStorage;
use std::{error::Error, path::PathBuf, sync::Arc};

fn init_storage(db_id: &str) -> Result<Arc<NodeStorage>, Box<dyn Error>> {
    let core_db = Arc::new(CoreDB::open(
        PathBuf::from(format!("./.rocksdb/{db_id}")),
        RocksDBOpts::default(),
    )?);
    let header_db = BlockHeaderDB::new(core_db.clone(), HEADER_CF_NAME, 1024, None);
    let xt_db = XtDB::new(core_db.clone(), XT_CF_NAME, 1024);
    let post_state_root_db = PostStateRootDB::new(core_db.clone(), POST_STATE_ROOT_CF_NAME, 1024);
    let state_manager = StateManager::from_core_db(core_db, StateManagerConfig::default());
    let _xt_pool = XtPool::new(1024);

    Ok(Arc::new(NodeStorage::new(
        Arc::new(state_manager),
        Arc::new(header_db),
        Arc::new(xt_db),
        Arc::new(post_state_root_db),
    )))
}

async fn set_genesis_state(jam_node: &JamNode) -> Result<(), Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block_from_file().header;
    let genesis_header_hash = genesis_header.hash()?;
    let storage = jam_node.storage();
    storage.header_db().set_best_header(genesis_header.clone());
    storage.header_db().commit_header(genesis_header).await?;

    // Set genesis extrinsics entry
    storage
        .xt_db()
        .set_xt(&Hash32::default(), Extrinsics::default())
        .await?;

    // Init genesis simple state with initial validators: active set, staging set and Safrole pending set
    add_all_simple_state_entries(&storage.state_manager(), Some(genesis_simple_state())).await?;

    // Commit genesis state
    storage.state_manager().commit_dirty_cache().await?;

    // Commit posterior state root of the genesis block
    let post_state_root = storage.state_manager().merkle_root();
    storage
        .post_state_root_db()
        .set_post_state_root(&genesis_header_hash, post_state_root)
        .await?;
    Ok(())
}

pub async fn init_node(
    node_account: Option<DevNodeAccountProfile>,
) -> Result<JamNode, Box<dyn Error>> {
    let node_info = match &node_account {
        Some(account) => account.load_validator_key_info(),
        None => {
            panic!("Dev account is not set.");
        }
    };

    let socket_addr = node_info.socket_addr;
    let node_storage =
        init_storage(format!("[{}]:{}", socket_addr.ip(), socket_addr.port()).as_str())?;
    tracing::info!("Storage initialized");
    let network_manager =
        NetworkManager::new(node_info.clone(), QuicEndpoint::new(socket_addr)).await?;
    let mut node = JamNode::new(node_info.clone(), node_storage, Arc::new(network_manager));
    tracing::info!("Node initialized\n[ValidatorInfo]\nSocket Address: {}\nBandersnatch Key: 0x{}\nEd25519 Key: 0x{}\n", node.network_manager().local_node_info.socket_addr, node.network_manager().local_node_info.validator_key.bandersnatch_key.to_hex(), node.network_manager().local_node_info.validator_key.ed25519_key.to_hex());

    // Set genesis state
    set_genesis_state(&node).await?;
    tracing::info!("Genesis state set");

    // Set the local node's validator index based on the genesis active set
    let curr_epoch_validator_index = node
        .storage()
        .state_manager()
        .get_active_set_clean()
        .await?
        .get_validator_index(node_info.bandersnatch_key());
    node.set_curr_epoch_validator_index(curr_epoch_validator_index);

    // Load initial validator peers from the genesis validator set state
    node.network_manager()
        .load_validator_peers(node.storage(), socket_addr)
        .await?;
    tracing::info!("Validator peers info loaded");
    Ok(node)
}
