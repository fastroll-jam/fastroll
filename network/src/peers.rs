use crate::streams::{LocalNodeRole, UpStream, UpStreamKind};
use fr_codec::prelude::*;
use fr_crypto::types::{Ed25519PubKey, ValidatorKeySet};
use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddrV6},
    ops::Deref,
};

pub struct AllValidatorPeers(pub HashMap<Ed25519PubKey, ValidatorPeer>);

impl Deref for AllValidatorPeers {
    type Target = HashMap<Ed25519PubKey, ValidatorPeer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ActiveEpochValidatorPeerKeys> for AllValidatorPeers {
    fn from(peers: ActiveEpochValidatorPeerKeys) -> Self {
        let mut all_peers = HashMap::new();
        all_peers.extend(peers.prev_epoch.0);
        all_peers.extend(peers.curr_epoch.0);
        all_peers.extend(peers.next_epoch.0);
        Self(all_peers)
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
pub struct EpochValidatorPeerKeys(pub HashMap<Ed25519PubKey, ValidatorPeer>);

impl Deref for EpochValidatorPeerKeys {
    type Target = HashMap<Ed25519PubKey, ValidatorPeer>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ValidatorKeySet> for EpochValidatorPeerKeys {
    fn from(value: ValidatorKeySet) -> Self {
        Self(
            value
                .iter()
                .map(|k| {
                    let ipv6: [u8; 16] = k.metadata.0[0..16].try_into().unwrap();
                    let port = u16::decode_fixed(&mut &k.metadata.0[16..18], 2).unwrap();
                    let ed25519_key = k.ed25519_key.clone();
                    (
                        ed25519_key.clone(),
                        ValidatorPeer::new(
                            ed25519_key,
                            SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0),
                            None,
                        ),
                    )
                })
                .collect(),
        )
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
}

/// A connection to a peer with UP stream handles.
#[derive(Debug)]
pub struct PeerConnection {
    pub conn: quinn::Connection,
    pub local_node_role: LocalNodeRole,
    pub up_stream_handles: HashMap<UpStreamKind, UpStream>,
}

impl PeerConnection {
    pub fn new(
        conn: quinn::Connection,
        local_node_role: LocalNodeRole,
        up_streams: HashMap<UpStreamKind, UpStream>,
    ) -> Self {
        Self {
            conn,
            local_node_role,
            up_stream_handles: up_streams,
        }
    }
}

#[derive(Default)]
pub struct Builders {
    pub inner: Vec<quinn::Connection>,
}
