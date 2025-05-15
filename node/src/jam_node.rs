use crate::roles::manager::RoleManager;
use fr_block::header_db::BlockHeaderDB;
use fr_network::manager::NetworkManager;
use fr_state::manager::StateManager;
use std::sync::Arc;

pub struct JamNode {
    pub state_manager: Arc<StateManager>,
    pub header_db: Arc<BlockHeaderDB>,
    pub network_manager: Arc<NetworkManager>,
    pub role_manager: Arc<RoleManager>,
}

impl JamNode {
    pub fn new(
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        network_manager: Arc<NetworkManager>,
        role_manager: Arc<RoleManager>,
    ) -> Self {
        Self {
            state_manager,
            header_db,
            network_manager,
            role_manager,
        }
    }
}
