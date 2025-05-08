use crate::error::NetworkError;
use fr_codec::prelude::*;
use fr_crypto::types::{Ed25519PubKey, ValidatorKey, ValidatorKeySet};
use fr_state::manager::StateManager;
use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

pub struct PeerManager {
    pub state_manager: Arc<StateManager>,
    pub peers: ValidatorPeers,
    pub builders: Builders,
}

impl PeerManager {
    pub async fn new(state_manager: Arc<StateManager>) -> Result<Self, NetworkError> {
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
            peers,
            builders: Builders::default(),
        })
    }
}

pub struct ValidatorPeers {
    pub prev_epoch: Option<EpochValidatorPeers>,
    pub curr_epoch: Option<EpochValidatorPeers>,
    pub next_epoch: Option<EpochValidatorPeers>,
}

impl ValidatorPeer {
    pub fn progress_epoch(&mut self) {
        unimplemented!()
    }
}

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

pub struct ValidatorPeer {
    pub validator_key: ValidatorKey,
    pub socket_addr: SocketAddrV6,
    pub connection: Option<quinn::Connection>,
}

impl ValidatorPeer {
    pub fn new(
        validator_key: ValidatorKey,
        socket_addr: SocketAddrV6,
        connection: Option<quinn::Connection>,
    ) -> Self {
        Self {
            validator_key,
            socket_addr,
            connection,
        }
    }
}

#[derive(Default)]
pub struct Builders {
    pub inner: Vec<quinn::Connection>,
}
