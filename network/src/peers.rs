use crate::streams::{LocalNodeRole, UpStream, UpStreamKind};
use fr_codec::prelude::*;
use fr_crypto::types::{Ed25519PubKey, ValidatorKey, ValidatorKeySet};
use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddrV6},
};

#[derive(Debug)]
pub struct ValidatorPeers {
    pub prev_epoch: Option<EpochValidatorPeers>,
    pub curr_epoch: Option<EpochValidatorPeers>,
    pub next_epoch: Option<EpochValidatorPeers>,
}

impl ValidatorPeers {
    pub fn progress_epoch(&mut self) {
        unimplemented!()
    }

    pub fn all_peers(&self) -> HashMap<&Ed25519PubKey, &ValidatorPeer> {
        [&self.prev_epoch, &self.curr_epoch, &self.next_epoch]
            .iter()
            .filter_map(|&maybe_peers| maybe_peers.as_ref())
            .flat_map(|peers| peers.inner.iter())
            .collect()
    }
}

#[derive(Debug)]
pub struct EpochValidatorPeers {
    pub inner: HashMap<Ed25519PubKey, ValidatorPeer>,
}

impl From<ValidatorKeySet> for EpochValidatorPeers {
    fn from(value: ValidatorKeySet) -> Self {
        Self {
            inner: value
                .iter()
                .map(|k| {
                    let ipv6: [u8; 16] = k.metadata.0[0..16].try_into().unwrap();
                    let port = u16::decode_fixed(&mut &k.metadata.0[16..18], 2).unwrap();
                    (
                        k.ed25519_key.clone(),
                        ValidatorPeer::new(
                            k.clone(),
                            SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0),
                            None,
                        ),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct ValidatorPeer {
    pub validator_key: ValidatorKey,
    pub socket_addr: SocketAddrV6,
    pub conn: Option<PeerConnection>,
}

impl ValidatorPeer {
    pub fn new(
        validator_key: ValidatorKey,
        socket_addr: SocketAddrV6,
        conn: Option<PeerConnection>,
    ) -> Self {
        Self {
            validator_key,
            socket_addr,
            conn,
        }
    }

    pub fn ed25519_key(&self) -> &Ed25519PubKey {
        &self.validator_key.ed25519_key
    }
}

#[derive(Debug)]
pub struct PeerConnection {
    pub conn: quinn::Connection,
    pub local_node_role: LocalNodeRole,
    pub up_streams: HashMap<UpStreamKind, UpStream>,
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
            up_streams,
        }
    }
}

#[derive(Default)]
pub struct Builders {
    pub inner: Vec<quinn::Connection>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_common::ByteEncodable;

    fn create_test_key(id: u8) -> Ed25519PubKey {
        let mut bytes = [0; 32];
        bytes[0] = id;
        Ed25519PubKey::from_slice(&bytes).unwrap()
    }

    fn create_test_peer(key: Ed25519PubKey, port: u16) -> ValidatorPeer {
        ValidatorPeer {
            validator_key: ValidatorKey {
                ed25519_key: key,
                ..Default::default()
            },
            socket_addr: SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0),
            conn: None,
        }
    }

    #[test]
    fn test_aggregate_all_peers() {
        let key1 = create_test_key(0);
        let key2 = create_test_key(1);
        let key3 = create_test_key(2);
        let key4 = create_test_key(3);

        let curr_epoch_peers = HashMap::from([
            (key1.clone(), create_test_peer(key1.clone(), 0)),
            (key2.clone(), create_test_peer(key2.clone(), 1)),
            (key3.clone(), create_test_peer(key3.clone(), 2)),
        ]);
        let next_epoch_peers = HashMap::from([
            (key2.clone(), create_test_peer(key2.clone(), 1)),
            (key3.clone(), create_test_peer(key3.clone(), 2)),
            (key4.clone(), create_test_peer(key4.clone(), 3)),
        ]);
        let validator_peers = ValidatorPeers {
            prev_epoch: None,
            curr_epoch: Some(EpochValidatorPeers {
                inner: curr_epoch_peers,
            }),
            next_epoch: Some(EpochValidatorPeers {
                inner: next_epoch_peers,
            }),
        };

        let all_peers = validator_peers.all_peers();

        let peer1 = create_test_peer(key1.clone(), 0);
        let peer2 = create_test_peer(key2.clone(), 1);
        let peer3 = create_test_peer(key3.clone(), 2);
        let peer4 = create_test_peer(key4.clone(), 3);
        let expected = HashMap::from([
            (&key1, &peer1),
            (&key2, &peer2),
            (&key3, &peer3),
            (&key4, &peer4),
        ]);
        for key in [&key1, &key2, &key3, &key4] {
            let peer = all_peers.get(key).cloned().unwrap();
            let expected_peer = expected.get(key).cloned().unwrap();
            assert_eq!(
                peer.validator_key.ed25519_key,
                expected_peer.validator_key.ed25519_key
            );
            assert_eq!(peer.socket_addr, expected_peer.socket_addr);
        }
    }
}
