use fr_block::header_db::BlockHeaderDB;
use fr_common::ValidatorIndex;
use fr_network::manager::{LocalNodeInfo, NetworkManager};
use fr_state::manager::StateManager;
use std::sync::Arc;

pub struct JamNode {
    pub curr_epoch_validator_index: Option<ValidatorIndex>,
    pub local_node_info: LocalNodeInfo,
    pub state_manager: Arc<StateManager>,
    pub header_db: Arc<BlockHeaderDB>,
    pub network_manager: Arc<NetworkManager>,
}

impl JamNode {
    pub fn new(
        local_node_info: LocalNodeInfo,
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        network_manager: Arc<NetworkManager>,
    ) -> Self {
        Self {
            curr_epoch_validator_index: None,
            local_node_info,
            state_manager,
            header_db,
            network_manager,
        }
    }

    pub fn set_curr_epoch_validator_index(&mut self, index: Option<ValidatorIndex>) {
        self.curr_epoch_validator_index = index;
    }
}
