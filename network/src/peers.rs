use crate::{error::NetworkError, streams::LocalNodeRole};
use dashmap::DashMap;
use fr_crypto::types::{Ed25519PubKey, ValidatorKey};
use std::{
    net::SocketAddrV6,
    ops::{Deref, DerefMut},
};

#[derive(Default)]
pub struct AllValidatorPeers(pub DashMap<SocketAddrV6, ValidatorPeer>);

impl Deref for AllValidatorPeers {
    type Target = DashMap<SocketAddrV6, ValidatorPeer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AllValidatorPeers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AllValidatorPeers {
    pub fn store_peer_connection_handle(
        &self,
        socket_addr: &SocketAddrV6,
        conn: PeerConnection,
    ) -> Result<(), NetworkError> {
        if let Some(mut peer) = self.get_mut(socket_addr) {
            peer.conn = Some(conn);
            Ok(())
        } else {
            Err(NetworkError::ValidatorPeerKeyNotFound)
        }
    }
}

#[derive(Debug)]
pub struct ActiveEpochValidatorPeerKeys {
    pub prev_epoch: EpochValidatorPeerKeys,
    pub curr_epoch: EpochValidatorPeerKeys,
    pub next_epoch: EpochValidatorPeerKeys,
}

impl ActiveEpochValidatorPeerKeys {
    pub fn progress_epoch(&mut self) {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct EpochValidatorPeerKeys(pub Vec<Ed25519PubKey>);

impl Deref for EpochValidatorPeerKeys {
    type Target = Vec<Ed25519PubKey>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct ValidatorPeer {
    pub ed25519_key: Ed25519PubKey,
    pub socket_addr: SocketAddrV6,
    pub conn: Option<PeerConnection>,
}

impl ValidatorPeer {
    pub fn new(
        ed25519_key: Ed25519PubKey,
        socket_addr: SocketAddrV6,
        conn: Option<PeerConnection>,
    ) -> Self {
        Self {
            ed25519_key,
            socket_addr,
            conn,
        }
    }

    pub fn from_validator_key(validator_key: ValidatorKey) -> Self {
        Self {
            ed25519_key: validator_key.ed25519_key,
            socket_addr: validator_key.metadata.socket_address(),
            conn: None,
        }
    }
}

/// A connection to a peer.
#[derive(Debug)]
pub struct PeerConnection {
    pub conn: quinn::Connection,
    pub local_node_role: LocalNodeRole,
}

impl PeerConnection {
    pub fn new(conn: quinn::Connection, local_node_role: LocalNodeRole) -> Self {
        Self {
            conn,
            local_node_role,
        }
    }
}

#[derive(Default)]
pub struct Builders {
    pub inner: Vec<quinn::Connection>,
}
