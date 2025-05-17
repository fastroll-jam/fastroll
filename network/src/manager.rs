use crate::{
    endpoint::QuicEndpoint,
    error::NetworkError,
    peers::{AllValidatorPeers, Builders, LocalNodeRole, PeerConnection},
    streams::{StreamKind, UpStreamHandle, UpStreamHandler, UpStreamKind},
    utils::{preferred_initiator, validator_set_to_peers},
};
use core::net::SocketAddr;
use dashmap::DashMap;
use fr_block::types::block::BlockHeader;
use fr_crypto::types::{BandersnatchPubKey, Ed25519PubKey, ValidatorKey};
use fr_state::manager::StateManager;
use std::{
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};
use tokio::sync::mpsc;

const UP_0_MPSC_BUFFER_SIZE: usize = 1024;

pub struct NetworkManager {
    pub local_node_info: LocalNodeInfo,
    pub endpoint: QuicEndpoint,
    pub all_validator_peers: Arc<AllValidatorPeers>,
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
            all_validator_peers: Arc::new(AllValidatorPeers::default()),
            builders: Builders::default(),
        })
    }

    pub async fn load_validator_peers(
        &self,
        state_manager: Arc<StateManager>,
        local_node_socket_addr: SocketAddrV6,
    ) -> Result<(), NetworkError> {
        // TODO: Predict validator set update on epoch progress
        let past_set = state_manager.get_past_set().await?;
        let active_set = state_manager.get_active_set().await?;
        let staging_set = state_manager.get_staging_set().await?;

        let mut all_validator_peers = DashMap::new();
        let prev_epoch_peers = validator_set_to_peers(past_set.0);
        let curr_epoch_peers = validator_set_to_peers(active_set.0);
        let next_epoch_peers = validator_set_to_peers(staging_set.0);
        all_validator_peers.extend(prev_epoch_peers);
        all_validator_peers.extend(curr_epoch_peers);
        all_validator_peers.extend(next_epoch_peers);

        for (socket_addr, peer) in all_validator_peers.into_iter() {
            // TODO: remove the comparison between default_socket_addr after updating validator set types to have empty vec as a default value
            let default_socket_addr =
                SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0, 0, 0);
            if socket_addr != local_node_socket_addr && socket_addr != default_socket_addr {
                self.all_validator_peers.insert(socket_addr, peer);
            }
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
            let all_peers_cloned = self.all_validator_peers.clone();
            tokio::spawn(async move { Self::handle_connection(conn, all_peers_cloned).await });
        }
        Ok(())
    }

    async fn handle_connection(
        incoming_conn: quinn::Incoming,
        all_peers: Arc<AllValidatorPeers>,
    ) -> Result<(), NetworkError> {
        let conn = incoming_conn.await?;
        let SocketAddr::V6(socket_addr) = conn.remote_address() else {
            return Err(NetworkError::InvalidPeerAddrFormat);
        };
        tracing::info!(
            "🔌 [Acceptor] Connected to a peer [{}]:{}",
            socket_addr.ip(),
            socket_addr.port()
        );

        // Store the accepted connection handle
        all_peers.store_peer_connection_handle(
            &socket_addr,
            PeerConnection::new(conn.clone(), LocalNodeRole::Acceptor, DashMap::default()),
        )?;

        // TODO: Monitor connection closure
        while let Ok((send_stream, mut recv_stream)) = conn.accept_bi().await {
            // Open a mpsc channel to route outgoing QUIC stream messages initiated by the internal system.
            let (mpsc_send, mpsc_recv) = mpsc::channel::<Vec<u8>>(UP_0_MPSC_BUFFER_SIZE);
            let all_peers_cloned = all_peers.clone();
            tokio::spawn(async move {
                let mut stream_kind_buf = [0u8; 1];
                if let Err(e) = recv_stream.read_exact(&mut stream_kind_buf).await {
                    tracing::error!("Failed to read a single-byte stream-kind identifier: {e}");
                    return;
                }
                let Ok(stream_kind) = StreamKind::from_u8(stream_kind_buf[0]) else {
                    tracing::error!("Invalid stream-kind identifier: {}", stream_kind_buf[0]);
                    return;
                };
                match stream_kind {
                    StreamKind::UP(stream_kind) => {
                        tracing::info!("💡 Accepted a UP stream. StreamKind: {stream_kind:?}");
                        // Insert UpStreamHandle which contains mpsc sender handle to initiate outgoing QUIC stream message.
                        if let Err(e) = all_peers_cloned.insert_up_stream_handle(
                            &socket_addr,
                            stream_kind,
                            UpStreamHandle::new(stream_kind, mpsc_send.clone()),
                        ) {
                            tracing::error!("Failed to insert upstream handle: {e}");
                        }
                        UpStreamHandler::handle_up_stream(
                            stream_kind,
                            send_stream,
                            recv_stream,
                            mpsc_recv,
                        );
                    }
                    StreamKind::CE(stream_kind) => {
                        tracing::info!("💡 Accepted a CE stream. StreamKind: {stream_kind:?}");
                        unimplemented!()
                    }
                }
                tracing::info!("🧨 Handling connection...");
            });
        }
        Ok(())
    }

    /// Connect to all network peers if the local node is the preferred initiator.
    pub async fn connect_to_peers(&self) -> Result<(), NetworkError> {
        tracing::info!("Connecting to peers...");
        let local_node_ed25519_key = self.local_node_ed25519_key().clone();

        let mut handles = Vec::with_capacity(self.all_validator_peers.len());
        for entry in self.all_validator_peers.iter() {
            let peer = entry.value();
            if peer.conn.is_none()
                && &local_node_ed25519_key
                    == preferred_initiator(&local_node_ed25519_key, &peer.ed25519_key)
                && local_node_ed25519_key != peer.ed25519_key
            {
                let endpoint_cloned = self.endpoint.clone();
                let all_peers_cloned = self.all_validator_peers.clone();
                let peer_socket_addr_cloned = peer.socket_addr;
                let peer_key_cloned = peer.ed25519_key.clone();
                let jh = tokio::spawn(async move {
                    Self::connect_to_peer(
                        endpoint_cloned,
                        all_peers_cloned,
                        peer_socket_addr_cloned,
                        &peer_key_cloned,
                    )
                    .await
                });
                handles.push(jh);
            }
        }
        for handle in handles {
            handle.await??;
        }
        Ok(())
    }

    /// Connect to all network peers that are not yet connected regardless of preferred initiator.
    pub async fn connect_to_all_peers(&self) -> Result<(), NetworkError> {
        tracing::info!("Connecting to all peers...");
        let local_node_ed25519_key = self.local_node_ed25519_key().clone();

        let mut handles = Vec::with_capacity(self.all_validator_peers.len());
        for entry in self.all_validator_peers.iter() {
            let peer = entry.value();
            if peer.conn.is_none() && local_node_ed25519_key != peer.ed25519_key {
                let endpoint_cloned = self.endpoint.clone();
                let all_peers_cloned = self.all_validator_peers.clone();
                let peer_socket_addr_cloned = peer.socket_addr;
                let peer_key_cloned = peer.ed25519_key.clone();
                let jh = tokio::spawn(async move {
                    Self::connect_to_peer(
                        endpoint_cloned,
                        all_peers_cloned,
                        peer_socket_addr_cloned,
                        &peer_key_cloned,
                    )
                    .await
                });
                handles.push(jh);
            }
        }
        for handle in handles {
            handle.await??;
        }
        // Debugging: check all connected peers
        for e in self.all_validator_peers.iter() {
            tracing::debug!(
                "SocketAddr: {}, connected: {}",
                e.socket_addr,
                e.conn.is_some()
            );
        }
        Ok(())
    }

    /// Establishes a connection with a peer and open UP bi-streams. Once the connection is established
    /// and UP streams are open, store those handles into `AllValidatorPeers`.
    async fn connect_to_peer(
        endpoint: QuicEndpoint,
        all_peers: Arc<AllValidatorPeers>,
        peer_addr: SocketAddrV6,
        peer_key: &Ed25519PubKey,
    ) -> Result<(), NetworkError> {
        let conn = endpoint.connect(peer_addr, peer_key).await?;
        let SocketAddr::V6(socket_addr) = conn.remote_address() else {
            return Err(NetworkError::InvalidPeerAddrFormat);
        };
        tracing::info!(
            "🔌 [Initiator] Connected to a peer [{}]:{}",
            socket_addr.ip(),
            socket_addr.port()
        );

        let (mut send_stream, recv_stream) = conn.open_bi().await?;

        // Send a single-byte stream kind identifier to the peer so that it can accept the stream.
        let stream_kind = UpStreamKind::BlockAnnouncement;
        let stream_kind_byte = vec![stream_kind as u8];
        send_stream.write_all(&stream_kind_byte).await?;

        // Store the opened connection handle
        all_peers.store_peer_connection_handle(
            &socket_addr,
            PeerConnection::new(conn, LocalNodeRole::Initiator, DashMap::default()),
        )?;
        // Store the UP stream handle
        let (mpsc_send, mpsc_recv) = mpsc::channel::<Vec<u8>>(UP_0_MPSC_BUFFER_SIZE);
        all_peers.insert_up_stream_handle(
            &socket_addr,
            stream_kind,
            UpStreamHandle::new(stream_kind, mpsc_send),
        )?;

        UpStreamHandler::handle_up_stream(stream_kind, send_stream, recv_stream, mpsc_recv);
        Ok(())
    }

    fn local_node_ed25519_key(&self) -> &Ed25519PubKey {
        &self.local_node_info.validator_key.ed25519_key
    }

    pub async fn announce_block_to_all_peers(
        &self,
        block_header: &BlockHeader,
    ) -> Result<(), NetworkError> {
        tracing::debug!("Sending block announcement via mpsc channel...");
        for peer in self.all_validator_peers.iter() {
            if let Some(conn) = &peer.value().conn {
                if let Some(handle_ref) =
                    conn.up_stream_handles.get(&UpStreamKind::BlockAnnouncement)
                {
                    let handle = handle_ref.value();
                    handle
                        .send_block_announcement(block_header.block_announcement_blob()?)
                        .await?
                }
            }
        }

        Ok(())
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

    pub fn bandersnatch_key(&self) -> &BandersnatchPubKey {
        &self.validator_key.bandersnatch_key
    }
}
