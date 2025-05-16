use fr_network::manager::LocalNodeInfo;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{SlotSealer, Timeslot},
};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RoleManagerError {
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

pub struct RoleManager {
    local_node_info: LocalNodeInfo,
    state_manager: Arc<StateManager>,
}

impl RoleManager {
    pub fn new(local_node_info: LocalNodeInfo, state_manager: Arc<StateManager>) -> Self {
        Self {
            local_node_info,
            state_manager,
        }
    }

    pub async fn is_author_of_slot(
        &self,
        new_timeslot: &Timeslot,
    ) -> Result<bool, RoleManagerError> {
        let slot_sealer = self
            .state_manager
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(new_timeslot);

        // TODO: impl for ticket mode
        match slot_sealer {
            SlotSealer::Ticket(_ticket) => {
                unimplemented!()
            }
            SlotSealer::BandersnatchPubKeys(key) => {
                Ok(self.local_node_info.bandersnatch_key() == &key)
            }
        }
    }
}
