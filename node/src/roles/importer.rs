use crate::utils::spawn_timed;
use rjam_block::{
    header_db::BlockHeaderDB,
    types::{block::Block, extrinsics::ExtrinsicsError},
};
use rjam_extrinsics::validation::{
    assurances::AssurancesXtValidator, disputes::DisputesXtValidator, error::XtError,
    guarantees::GuaranteesXtValidator, preimages::PreimagesXtValidator,
    tickets::TicketsXtValidator,
};
use rjam_state::{error::StateManagerError, manager::StateManager};
use std::sync::Arc;
use thiserror::Error;
use tokio::try_join;

#[derive(Debug, Error)]
pub enum BlockImportError {
    #[error("Block header contains invalid xt hash")]
    InvalidXtHash,
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
    #[error("XtError: {0}")]
    XtError(#[from] XtError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[allow(dead_code)]
struct BlockImporter {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
    block: Block,
}

#[allow(dead_code)]
impl BlockImporter {
    pub fn new(
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        latest_block: Option<Block>,
    ) -> Self {
        Self {
            state_manager,
            header_db,
            block: latest_block.unwrap_or_default(),
        }
    }

    pub fn import_block(&mut self, block: Block) {
        self.block = block;
    }

    pub async fn validate_block(&self) -> Result<(), BlockImportError> {
        self.validate_block_header()?;
        self.validate_xts().await?;
        Ok(())
    }

    fn validate_block_header(&self) -> Result<(), BlockImportError> {
        self.validate_timeslot_index()?;
        self.validate_prior_state_root()?;
        self.verify_xt_hash()?;
        Ok(())
    }

    fn validate_timeslot_index(&self) -> Result<(), BlockImportError> {
        Ok(())
    }

    fn validate_prior_state_root(&self) -> Result<(), BlockImportError> {
        Ok(())
    }

    /// Note: Currently, each STF validates Xt types as well.
    async fn validate_xts(&self) -> Result<(), BlockImportError> {
        let prior_timeslot = self.state_manager.get_timeslot_clean().await?;
        let curr_timeslot_index = self.block.header.timeslot_index();

        // Clone necessary data to spawn async tasks
        let parent_hash = self.block.header.parent_hash().clone();
        let tickets = self.block.extrinsics.tickets.clone();
        let preimages = self.block.extrinsics.preimages.clone();
        let guarantees = self.block.extrinsics.guarantees.clone();
        let assurances = self.block.extrinsics.assurances.clone();
        let disputes = self.block.extrinsics.disputes.clone();

        let tickets_validator = TicketsXtValidator::new(self.state_manager.clone());
        let preimages_validator = PreimagesXtValidator::new(self.state_manager.clone());
        let guarantees_validator = GuaranteesXtValidator::new(self.state_manager.clone());
        let assurances_validator = AssurancesXtValidator::new(self.state_manager.clone());
        let disputes_validator = DisputesXtValidator::new(self.state_manager.clone());

        let tickets_jh = spawn_timed("validate_tickets", async move {
            tickets_validator.validate(&tickets).await
        });
        let preimages_jh = spawn_timed("validate_preimages", async move {
            preimages_validator.validate(&preimages).await
        });
        let guarantees_jh = spawn_timed("validate_guarantees", async move {
            guarantees_validator
                .validate(&guarantees, curr_timeslot_index)
                .await
        });
        let assurances_jh = spawn_timed("validate_assurances", async move {
            assurances_validator
                .validate(&assurances, &parent_hash)
                .await
        });
        let disputes_jh = spawn_timed("validate_disputes", async move {
            disputes_validator
                .validate(&disputes, &prior_timeslot)
                .await
        });

        #[allow(unused_must_use)]
        try_join!(
            tickets_jh,
            preimages_jh,
            guarantees_jh,
            assurances_jh,
            disputes_jh
        )?;
        Ok(())
    }

    fn verify_xt_hash(&self) -> Result<(), BlockImportError> {
        if self.block.header.extrinsic_hash() != &self.block.extrinsics.hash()? {
            return Err(BlockImportError::InvalidXtHash);
        }
        Ok(())
    }

    fn verify_block_seal(&self) -> Result<(), BlockImportError> {
        Ok(())
    }

    fn verify_vrf_output(&self) -> Result<(), BlockImportError> {
        Ok(())
    }
}

pub async fn run_state_transition() {}
