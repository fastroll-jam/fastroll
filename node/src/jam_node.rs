use fr_common::ValidatorIndex;
use fr_network::{
    error::NetworkError,
    manager::{LocalNodeInfo, NetworkManager},
};
use fr_storage::node_storage::NodeStorage;
use std::sync::Arc;

pub struct JamNode {
    pub curr_epoch_validator_index: Option<ValidatorIndex>,
    local_node_info: LocalNodeInfo,
    storage: Arc<NodeStorage>,
    network_manager: Arc<NetworkManager>,
}

impl JamNode {
    pub fn new(
        local_node_info: LocalNodeInfo,
        storage: Arc<NodeStorage>,
        network_manager: Arc<NetworkManager>,
    ) -> Self {
        Self {
            curr_epoch_validator_index: None,
            local_node_info,
            storage,
            network_manager,
        }
    }

    pub fn local_node_info(&self) -> &LocalNodeInfo {
        &self.local_node_info
    }

    pub fn storage(&self) -> Arc<NodeStorage> {
        self.storage.clone()
    }

    pub fn network_manager(&self) -> Arc<NetworkManager> {
        self.network_manager.clone()
    }

    pub fn set_curr_epoch_validator_index(&mut self, index: Option<ValidatorIndex>) {
        self.curr_epoch_validator_index = index;
    }

    pub async fn run_as_server(&self) -> Result<(), NetworkError> {
        tracing::info!(
            "📡 Listening on {}",
            self.network_manager.endpoint.local_addr()?
        );
        // Accept incoming connections
        let endpoint = self.network_manager.endpoint.clone();
        while let Some(conn) = endpoint.accept().await {
            tracing::info!("Accepted connection from {}", conn.remote_address());
            // Spawn an async task to handle the connection
            let all_peers_cloned = self.network_manager.all_validator_peers.clone();
            let storage_cloned = self.storage.clone();
            tokio::spawn(async move {
                NetworkManager::handle_connection(storage_cloned, conn, all_peers_cloned).await
            });
        }
        Ok(())
    }
}
