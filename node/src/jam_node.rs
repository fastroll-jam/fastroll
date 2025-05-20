use fr_common::ValidatorIndex;
use fr_network::manager::{LocalNodeInfo, NetworkManager};
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
}
