use crate::{
    endpoint::QuicEndpoint,
    error::NetworkError,
    peers::{Builders, PeerConnection, ValidatorPeers},
    streams::{LocalNodeRole, UpStream, UpStreamKind},
    utils::preferred_initiator,
};
use fr_crypto::types::{Ed25519PubKey, ValidatorKey};
use fr_state::manager::StateManager;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

pub struct NetworkManager {
    pub state_manager: Arc<StateManager>,
    pub local_node_info: LocalNodeInfo,
    pub endpoint: QuicEndpoint,
    pub peers: ValidatorPeers,
    pub builders: Builders,
}

impl NetworkManager {
    pub async fn new(
        state_manager: Arc<StateManager>,
        local_node_info: LocalNodeInfo,
        endpoint: QuicEndpoint,
    ) -> Result<Self, NetworkError> {
        // TODO: Predict validator set update on epoch progress
        let past_set = state_manager.get_past_set().await.ok();
        let active_set = state_manager.get_active_set().await.ok();
        let staging_set = state_manager.get_staging_set().await.ok();

        let peers = ValidatorPeers {
            prev_epoch: past_set.map(|set| set.0.into()),
            curr_epoch: active_set.map(|set| set.0.into()),
            next_epoch: staging_set.map(|set| set.0.into()),
        };

        Ok(Self {
            state_manager,
            local_node_info,
            endpoint,
            peers,
            builders: Builders::default(),
        })
    }

    pub async fn connect_to_peers(&self) -> Result<(), NetworkError> {
        let local_node_ed25519_key = self.local_node_ed25519_key();
        for (peer_key, peer) in self.peers.all_peers() {
            let preferred_initiator = preferred_initiator(local_node_ed25519_key, peer_key);
            if preferred_initiator == local_node_ed25519_key {
                let conn = self.endpoint.connect(peer.socket_addr, peer_key).await?;
                let (send_stream, recv_stream) = conn.open_bi().await?;
                let up_0_stream = UpStream {
                    stream_kind: UpStreamKind::BlockAnnouncement,
                    send_stream,
                    recv_stream,
                };
                let _peer_conn = PeerConnection::new(
                    conn,
                    LocalNodeRole::Initiator,
                    HashMap::from([(UpStreamKind::BlockAnnouncement, up_0_stream)]),
                );
            } else {
                // TODO: initiate when timed out
            }
        }

        Ok(())
    }

    fn local_node_ed25519_key(&self) -> &Ed25519PubKey {
        &self.local_node_info.validator_key.ed25519_key
    }
}

#[derive(Clone, Debug)]
pub struct LocalNodeInfo {
    pub socket_addr: SocketAddrV6,
    pub validator_key: ValidatorKey,
}

impl Display for LocalNodeInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ socket_addr: {:?}, validator_key: {} }}",
            self.socket_addr, self.validator_key
        )
    }
}

impl LocalNodeInfo {
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
