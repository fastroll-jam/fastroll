use crate::{
    endpoint::QuicEndpoint,
    error::NetworkError,
    peers::{AllValidatorPeers, Builders, PeerConnection},
    streams::{LocalNodeRole, UpStream, UpStreamKind},
    utils::{preferred_initiator, validator_set_to_peers},
};
use dashmap::DashMap;
use fr_crypto::types::{Ed25519PubKey, ValidatorKey};
use fr_state::manager::StateManager;
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

pub struct NetworkManager {
    pub local_node_info: LocalNodeInfo,
    pub endpoint: QuicEndpoint,
    pub all_validator_peers: AllValidatorPeers,
    pub builders: Builders,
}

impl NetworkManager {
    pub async fn new(
        local_node_info: LocalNodeInfo,
        endpoint: QuicEndpoint,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            local_node_info,
            endpoint,
            all_validator_peers: AllValidatorPeers::default(),
            builders: Builders::default(),
        })
    }

    pub async fn load_validator_peers(
        &self,
        state_manager: Arc<StateManager>,
    ) -> Result<(), NetworkError> {
        // TODO: Predict validator set update on epoch progress
        let past_set = state_manager.get_past_set().await.ok();
        let active_set = state_manager.get_active_set().await.ok();
        let staging_set = state_manager.get_staging_set().await.ok();

        let mut all_validator_peers = DashMap::new();
        let prev_epoch_peers = validator_set_to_peers(past_set.unwrap_or_default().0);
        let curr_epoch_peers = validator_set_to_peers(active_set.unwrap_or_default().0);
        let next_epoch_peers = validator_set_to_peers(staging_set.unwrap_or_default().0);
        all_validator_peers.extend(prev_epoch_peers);
        all_validator_peers.extend(curr_epoch_peers);
        all_validator_peers.extend(next_epoch_peers);

        for (key, peer) in all_validator_peers.into_iter() {
            self.all_validator_peers.insert(key, peer);
        }
        Ok(())
    }

    pub async fn run_as_server(&self) -> Result<(), NetworkError> {
        tracing::info!("📡 Listening on {}", self.endpoint.local_addr()?);
        // Accept incoming connections
        let endpoint = self.endpoint.clone();
        while let Some(conn) = endpoint.accept().await {
            tracing::info!("Accepted connection from {}", conn.remote_address());
            // Spawn an async task to handle the connection
            tokio::spawn(async move { Self::handle_connection(conn).await });
        }
        Ok(())
    }

    async fn handle_connection(conn: quinn::Incoming) -> Result<(), NetworkError> {
        let conn = conn.await?;
        tracing::info!(
            "🔌 Connected to a peer [{}]:{}",
            conn.remote_address().ip(),
            conn.remote_address().port()
        );
        while let Ok((_send, _recv)) = conn.accept_bi().await {
            // TODO: store the accepted UP stream handles in the `AllValidatorPeers`
            tracing::info!("💡 Accepted an UP stream!");
            tokio::spawn(async move {
                tracing::info!("🧨 Handling connection...");
            });
        }
        Ok(())
    }

    /// Connect to all network peers if the local node is the preferred initiator.
    pub async fn connect_to_peers(&self) -> Result<(), NetworkError> {
        tracing::info!("Connecting to peers...");
        tracing::trace!("All Peers: {:?}", self.all_validator_peers.0);
        let local_node_ed25519_key = self.local_node_ed25519_key().clone();
        for entry in self.all_validator_peers.iter() {
            let (peer_key, peer) = entry.pair();
            if peer.conn.is_none()
                && &local_node_ed25519_key == preferred_initiator(&local_node_ed25519_key, peer_key)
                && &local_node_ed25519_key != peer_key
            {
                self.connect_to_peer(peer.socket_addr, peer_key).await?;
            }
        }
        Ok(())
    }

    /// Connect to all network peers that are not yet connected regardless of preferred initiator.
    pub async fn connect_to_all_peers(&self) -> Result<(), NetworkError> {
        tracing::info!("Connecting to all peers...");
        tracing::trace!("All Peers: {:?}", self.all_validator_peers.0);
        let local_node_ed25519_key = self.local_node_ed25519_key().clone();
        for entry in self.all_validator_peers.iter() {
            let (peer_key, peer) = entry.pair();
            if peer.conn.is_none() && &local_node_ed25519_key != peer_key {
                self.connect_to_peer(peer.socket_addr, peer_key).await?;
            }
        }
        Ok(())
    }

    async fn connect_to_peer(
        &self,
        peer_addr: SocketAddrV6,
        peer_key: &Ed25519PubKey,
    ) -> Result<(), NetworkError> {
        let endpoint = self.endpoint.clone();
        let conn = endpoint.connect(peer_addr, peer_key).await?;
        tracing::info!(
            "🔌 Connected to a peer [{}]:{}",
            peer_addr.ip(),
            peer_addr.port()
        );
        let (mut send_stream, recv_stream) = conn.open_bi().await?;

        // Send initial request to the peer so that it can accept the stream.
        let init_request = "Hello".as_bytes().to_vec();
        send_stream.write_all(&init_request).await?;

        let up_0_stream = UpStream {
            stream_kind: UpStreamKind::BlockAnnouncement,
            send_stream,
            recv_stream,
        };
        let peer_conn = PeerConnection::new(
            conn,
            LocalNodeRole::Initiator,
            HashMap::from([(UpStreamKind::BlockAnnouncement, up_0_stream)]),
        );
        self.all_validator_peers
            .store_peer_connection_handle(peer_key, peer_conn)?;
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
