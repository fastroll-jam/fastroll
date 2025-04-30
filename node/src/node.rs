use rjam_block::header_db::BlockHeaderDB;
use rjam_crypto::types::ValidatorKey;
use rjam_state::manager::StateManager;
use std::{net::SocketAddrV6, sync::Arc};

#[allow(dead_code)]
struct ValidatorInfo {
    socket_addr_v6: SocketAddrV6,
    validator_key: ValidatorKey,
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

#[allow(dead_code)]
pub struct JamNode {
    validator_info: ValidatorInfo,
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
}
