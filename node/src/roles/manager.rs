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

pub struct RoleManager;
impl RoleManager {
    pub async fn is_author_of_slot(
        state_manager: Arc<StateManager>,
        local_node_info: LocalNodeInfo,
        new_timeslot: &Timeslot,
    ) -> Result<bool, RoleManagerError> {
        let slot_sealer = state_manager
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(new_timeslot);

        // TODO: impl for ticket mode
        match slot_sealer {
            SlotSealer::Ticket(_ticket) => {
                unimplemented!()
            }
            SlotSealer::BandersnatchPubKeys(key) => Ok(local_node_info.bandersnatch_key() == &key),
        }
    }
}
