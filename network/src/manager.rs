use crate::{
    error::NetworkError,
    peers::{Builders, ValidatorPeers},
};
use fr_state::manager::StateManager;
use std::sync::Arc;

pub struct NetworkManager {
    pub state_manager: Arc<StateManager>,
    pub peers: ValidatorPeers,
    pub builders: Builders,
}

impl NetworkManager {
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

    pub async fn connect_to_peers(&self) -> Result<(), NetworkError> {
        self.peers
            .all_peers()
            .iter()
            .for_each(|(&_key, &_peer)| todo!());
        Ok(())
    }
}
