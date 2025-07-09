use fr_block::types::block::Block;
use fr_common::ValidatorIndex;
use fr_network::{
    error::NetworkError,
    manager::{LocalNodeInfo, NetworkManager},
};
use fr_storage::node_storage::NodeStorage;
use std::sync::Arc;
use tokio::sync::mpsc;

pub mod config;
pub mod init;
pub mod runner;
pub mod ticket_store;

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

    pub async fn run_acceptor(
        &self,
        block_import_mpsc_sender: mpsc::Sender<Block>,
    ) -> Result<(), NetworkError> {
        tracing::info!(
            "📡 Listening on {}",
            self.network_manager.endpoint.local_addr()?
        );
        // Accept incoming connections
        let endpoint = self.network_manager.endpoint.clone();
        while let Some(incoming_conn) = endpoint.accept().await {
            tracing::debug!(
                "Accepted connection from {}",
                incoming_conn.remote_address()
            );
            // Spawn an async task to handle the connection
            let all_peers_cloned = self.network_manager.all_validator_peers.clone();
            let storage_cloned = self.storage.clone();
            let block_import_mpsc_sender_cloned = block_import_mpsc_sender.clone();
            tokio::spawn(async move {
                let conn = incoming_conn.await.unwrap();
                NetworkManager::accept_connection(
                    conn,
                    block_import_mpsc_sender_cloned,
                    all_peers_cloned,
                    storage_cloned,
                )
                .await
            });
        }
        Ok(())
    }

    pub async fn run_initiator(
        &self,
        block_import_mpsc_sender: mpsc::Sender<Block>,
    ) -> Result<(), NetworkError> {
        let network_manager = self.network_manager();
        let storage = self.storage();

        // Connect to peers as preferred initiator
        network_manager
            .connect_to_peers(block_import_mpsc_sender.clone(), storage.clone())
            .await?;

        // Wait until timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Connect to all remaining peers after timeout
        network_manager
            .connect_to_all_peers(block_import_mpsc_sender, storage)
            .await?;
        Ok(())
    }
}
