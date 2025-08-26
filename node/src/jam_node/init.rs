use crate::{
    genesis::{genesis_simple_state, load_genesis_block},
    jam_node::JamNode,
    keystore::dev_account_profile::DevNodeAccountProfile,
};
use fr_block::types::extrinsics::Extrinsics;
use fr_common::{ByteEncodable, Hash32};
use fr_config::{NodeConfig, StorageConfig};

use fr_network::{endpoint::QuicEndpoint, manager::NetworkManager};
use fr_state::state_utils::add_all_simple_state_entries;
use fr_storage::node_storage::NodeStorage;
use std::{error::Error, sync::Arc};

fn init_storage(cfg: StorageConfig) -> Result<Arc<NodeStorage>, Box<dyn Error>> {
    Ok(Arc::new(NodeStorage::new(cfg)?))
}

async fn set_genesis_state(jam_node: &JamNode) -> Result<(), Box<dyn Error>> {
    // Genesis header is the best header
    let genesis_header = load_genesis_block().header;
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
    node_account: DevNodeAccountProfile,
    db_path: &str,
) -> Result<JamNode, Box<dyn Error>> {
    let node_info = &node_account.load_validator_key_info();

    let socket_addr = node_info.socket_addr;
    let node_id = format!("[{}]:{}", socket_addr.ip(), socket_addr.port());
    let node_config = NodeConfig::from_node_id(node_id.as_str(), db_path);
    let node_storage = init_storage(node_config.storage)?;
    tracing::info!("Storage initialized");
    let network_manager =
        NetworkManager::new(node_info.clone(), QuicEndpoint::new(socket_addr)).await?;
    let mut node = JamNode::new(node_info.clone(), node_storage, Arc::new(network_manager));
    tracing::info!(
        "\
        Node initialized \n\
        [ValidatorInfo] \n\
        Socket Address: {} \n\
        Bandersnatch Key: 0x{} \n\
        Ed25519 Key: 0x{} \n",
        node.network_manager().local_node_info.socket_addr,
        node.network_manager()
            .local_node_info
            .validator_key
            .bandersnatch
            .to_hex(),
        node.network_manager()
            .local_node_info
            .validator_key
            .ed25519
            .to_hex()
    );

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
