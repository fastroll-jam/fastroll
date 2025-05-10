use crate::{
    endpoint::QuicEndpoint,
    error::NetworkError,
    peers::{AllValidatorPeers, Builders, PeerConnection},
    streams::{LocalNodeRole, UpStream, UpStreamKind},
    utils::{preferred_initiator, validator_set_to_peers},
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
    pub all_validator_peers: AllValidatorPeers,
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

        let mut all_validator_peers = HashMap::new();
        let prev_epoch_peers = validator_set_to_peers(past_set.unwrap_or_default().0);
        let curr_epoch_peers = validator_set_to_peers(active_set.unwrap_or_default().0);
        let next_epoch_peers = validator_set_to_peers(staging_set.unwrap_or_default().0);
        all_validator_peers.extend(prev_epoch_peers);
        all_validator_peers.extend(curr_epoch_peers);
        all_validator_peers.extend(next_epoch_peers);

        Ok(Self {
            state_manager,
            local_node_info,
            endpoint,
            all_validator_peers: AllValidatorPeers(all_validator_peers),
            builders: Builders::default(),
        })
    }

    pub async fn connect_to_peers(&self) -> Result<(), NetworkError> {
        let local_node_ed25519_key = self.local_node_ed25519_key();
        for (peer_key, peer) in self.all_validator_peers.iter() {
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
