use crate::roles::manager::RoleManager;
use fr_block::header_db::BlockHeaderDB;
use fr_network::manager::{LocalNodeInfo, NetworkManager};
use fr_state::manager::StateManager;
use std::sync::Arc;

pub struct JamNode {
    pub local_node_info: LocalNodeInfo,
    pub state_manager: Arc<StateManager>,
    pub header_db: Arc<BlockHeaderDB>,
    pub network_manager: Arc<NetworkManager>,
    pub role_manager: Arc<RoleManager>,
}

impl JamNode {
    pub fn new(
        local_node_info: LocalNodeInfo,
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        network_manager: Arc<NetworkManager>,
        role_manager: Arc<RoleManager>,
    ) -> Self {
        Self {
            local_node_info,
            state_manager,
            header_db,
            network_manager,
            role_manager,
        }
    }
}
