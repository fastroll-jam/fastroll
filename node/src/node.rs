use rjam_block::header_db::BlockHeaderDB;
use rjam_crypto::types::ValidatorKey;
use rjam_networking::endpoint::QuicEndpoint;
use rjam_state::manager::StateManager;
use std::{net::SocketAddrV6, sync::Arc};

#[allow(dead_code)]
pub struct ValidatorInfo {
    pub socket_addr_v6: SocketAddrV6,
    pub validator_key: ValidatorKey,
}

impl ValidatorInfo {
    #[allow(dead_code)]
    fn new(socket_addr_v6: SocketAddrV6, validator_key: ValidatorKey) -> Self {
        ValidatorInfo {
            socket_addr_v6,
            validator_key,
        }
    }
}

pub struct JamNode {
    pub validator_info: ValidatorInfo,
    pub state_manager: Arc<StateManager>,
    pub header_db: Arc<BlockHeaderDB>,
    pub endpoint: QuicEndpoint,
}

impl JamNode {
    pub fn new(
        validator_info: ValidatorInfo,
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        endpoint: QuicEndpoint,
    ) -> Self {
        Self {
            validator_info,
            state_manager,
            header_db,
            endpoint,
        }
    }
}
