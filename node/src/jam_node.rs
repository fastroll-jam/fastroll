use rjam_block::header_db::BlockHeaderDB;
use rjam_crypto::types::ValidatorKey;
use rjam_network::{endpoint::QuicEndpoint, peers::PeerManager};
use rjam_state::manager::StateManager;
use std::{
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub socket_addr: SocketAddrV6,
    pub validator_key: ValidatorKey,
}

impl Display for NodeInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ socket_addr: {:?}, validator_key: {} }}",
            self.socket_addr, self.validator_key
        )
    }
}

impl NodeInfo {
    pub fn new(socket_addr_v6: SocketAddrV6, validator_key: ValidatorKey) -> Self {
        Self {
            socket_addr: socket_addr_v6,
            validator_key,
        }
    }

    pub fn new_localhost(port: u16, validator_key: ValidatorKey) -> Self {
        Self {
            socket_addr: SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0),
            validator_key,
        }
    }
}

pub struct JamNode {
    pub node_info: NodeInfo,
    pub state_manager: Arc<StateManager>,
    pub header_db: Arc<BlockHeaderDB>,
    pub peer_manager: Arc<PeerManager>,
    pub endpoint: QuicEndpoint,
}

impl JamNode {
    pub fn new(
        validator_info: NodeInfo,
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        peer_manager: Arc<PeerManager>,
        endpoint: QuicEndpoint,
    ) -> Self {
        Self {
            node_info: validator_info,
            state_manager,
            header_db,
            peer_manager,
            endpoint,
        }
    }
}
