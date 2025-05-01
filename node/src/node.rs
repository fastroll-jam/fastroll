use rjam_block::header_db::BlockHeaderDB;
use rjam_crypto::types::ValidatorKey;
use rjam_network::endpoint::QuicEndpoint;
use rjam_state::manager::StateManager;
use std::{
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub socket_addr_v6: SocketAddrV6,
    pub validator_key: ValidatorKey,
}

impl Display for ValidatorInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ socket_addr_v6: {:?}, validator_key: {} }}",
            self.socket_addr_v6, self.validator_key
        )
    }
}

impl ValidatorInfo {
    pub fn new(socket_addr_v6: SocketAddrV6, validator_key: ValidatorKey) -> Self {
        Self {
            socket_addr_v6,
            validator_key,
        }
    }

    pub fn new_localhost(port: u16, validator_key: ValidatorKey) -> Self {
        Self {
            socket_addr_v6: SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0),
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
