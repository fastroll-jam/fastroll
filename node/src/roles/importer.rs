use crate::{
    roles::{
        author::author_block_seal_is_valid,
        executor::{BlockExecutionError, BlockExecutor},
    },
    utils::spawn_timed,
};
use rjam_block::{
    header_db::BlockHeaderDB,
    types::{
        block::{Block, BlockHeader, BlockHeaderError},
        extrinsics::ExtrinsicsError,
    },
};
use rjam_codec::prelude::*;
use rjam_common::{Hash32, HASH_SIZE, X_E, X_F, X_T};
use rjam_crypto::{
    error::CryptoError, traits::VrfSignature, types::BandersnatchPubKey,
    vrf::bandersnatch_vrf::VrfVerifier,
};
use rjam_extrinsics::validation::{
    assurances::AssurancesXtValidator, disputes::DisputesXtValidator, error::XtError,
    guarantees::GuaranteesXtValidator, preimages::PreimagesXtValidator,
    tickets::TicketsXtValidator,
};
use rjam_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{SlotSealer, Timeslot},
};
use std::sync::Arc;
use thiserror::Error;
use tokio::try_join;

#[derive(Debug, Error)]
pub enum BlockImportError {
    #[error("Block header contains invalid xt hash")]
    InvalidXtHash,
    #[error("Block header contains invalid author index")]
    InvalidAuthorIndex,
    #[error("Block header is sealed with invalid fallback key")]
    InvalidFallbackAuthorKey,
    #[error("Block header seal doesn't match the ticket")]
    InvalidBlockSealOutput,
    #[error("Best block is not found locally")]
    BestBlockNotFound,
    #[error("Block header contains invalid parent hash")]
    InvalidParentHash,
    #[error("Block header contains timeslot that is later than the current system time")]
    TimeslotInFuture,
    #[error("Block header contains timeslot earlier than the parent header")]
    InvalidTimeslot,
    #[error("XtError: {0}")]
    XtError(#[from] XtError),
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockExecutionError: {0}")]
    BlockExecutionError(#[from] BlockExecutionError),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[allow(dead_code)]
struct BlockImporter {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
    best_header: BlockHeader,
    curr_block: Block,
    curr_entropy_3: Hash32,
    curr_slot_sealer: SlotSealer,
    curr_author_bandersnatch_key: BandersnatchPubKey,
}

#[allow(dead_code)]
impl BlockImporter {
    pub fn new(
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        best_header: Option<BlockHeader>,
        latest_block: Option<Block>,
        latest_entropy_3: Option<Hash32>,
        latest_slot_sealer: Option<SlotSealer>,
        latest_author_bandersnatch_key: Option<BandersnatchPubKey>,
    ) -> Self {
        Self {
            state_manager,
            header_db,
            best_header: best_header.unwrap_or_default(),
            curr_block: latest_block.unwrap_or_default(),
            curr_entropy_3: latest_entropy_3.unwrap_or_default(),
            curr_slot_sealer: latest_slot_sealer.unwrap_or_default(),
            curr_author_bandersnatch_key: latest_author_bandersnatch_key.unwrap_or_default(),
        }
    }

    pub async fn import_block(&mut self, block: Block) -> Result<(), BlockImportError> {
        let best_header = self
            .header_db
            .get_best_header()
            .ok_or(BlockImportError::BestBlockNotFound)?;

        let curr_epoch_entropy = self.state_manager.get_epoch_entropy().await?;
        let curr_entropy_3 = curr_epoch_entropy.third_history();

        let curr_active_set = self.state_manager.get_active_set().await?;
        let author_index = block.header.author_index();
        let author_bandersnatch_key = curr_active_set
            .get_validator_bandersnatch_key(author_index)
            .ok_or(BlockImportError::InvalidAuthorIndex)?;

        let curr_safrole = self.state_manager.get_safrole().await?;
        let curr_timeslot = Timeslot::new(block.header.timeslot_index());
        let curr_slot_sealer = curr_safrole.slot_sealers.get_slot_sealer(&curr_timeslot);

        self.best_header = best_header;
        self.curr_block = block;
        self.curr_entropy_3 = curr_entropy_3.clone();
        self.curr_slot_sealer = curr_slot_sealer;
        self.curr_author_bandersnatch_key = author_bandersnatch_key.clone();

        Ok(())
    }

    pub async fn validate_block(&self) -> Result<(), BlockImportError> {
        self.validate_xts().await?;
        self.validate_block_header()?;
        Ok(())
    }

    /// Note: Currently, each STF validates Xt types as well.
    async fn validate_xts(&self) -> Result<(), BlockImportError> {
        let prior_timeslot = self.state_manager.get_timeslot_clean().await?;
        let curr_timeslot_index = self.curr_block.header.timeslot_index();

        // Clone necessary data to spawn async tasks
        let parent_hash = self.curr_block.header.parent_hash().clone();
        let tickets = self.curr_block.extrinsics.tickets.clone();
        let preimages = self.curr_block.extrinsics.preimages.clone();
        let guarantees = self.curr_block.extrinsics.guarantees.clone();
        let assurances = self.curr_block.extrinsics.assurances.clone();
        let disputes = self.curr_block.extrinsics.disputes.clone();

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

    fn validate_block_header(&self) -> Result<(), BlockImportError> {
        self.validate_parent_hash()?;
        self.validate_timeslot_index()?;
        self.validate_prior_state_root()?;
        self.verify_xt_hash()?;
        self.verify_block_seal()?;
        self.verify_vrf_output()?;
        Ok(())
    }

    fn validate_parent_hash(&self) -> Result<(), BlockImportError> {
        if self.curr_block.header.parent_hash() != &self.best_header.hash()? {
            return Err(BlockImportError::InvalidParentHash);
        };
        Ok(())
    }

    fn validate_timeslot_index(&self) -> Result<(), BlockImportError> {
        let current_timeslot_index = self.curr_block.header.timeslot_index();
        if current_timeslot_index <= self.best_header.timeslot_index() {
            return Err(BlockImportError::InvalidTimeslot);
        }
        if Timeslot::new(current_timeslot_index).is_in_future() {
            return Err(BlockImportError::TimeslotInFuture);
        }
        Ok(())
    }

    fn validate_prior_state_root(&self) -> Result<(), BlockImportError> {
        unimplemented!()
    }

    fn verify_xt_hash(&self) -> Result<(), BlockImportError> {
        if self.curr_block.header.extrinsic_hash() != &self.curr_block.extrinsics.hash()? {
            return Err(BlockImportError::InvalidXtHash);
        }
        Ok(())
    }

    fn verify_block_seal(&self) -> Result<(), BlockImportError> {
        let block_seal = &self.curr_block.header.block_seal;
        let entropy_3 = &self.curr_entropy_3;

        let vrf_input = match &self.curr_slot_sealer {
            SlotSealer::Ticket(ticket) => {
                if !author_block_seal_is_valid(block_seal, ticket) {
                    return Err(BlockImportError::InvalidBlockSealOutput);
                }
                let mut vrf_input = Vec::with_capacity(X_T.len() + entropy_3.len() + 1);
                vrf_input.extend_from_slice(X_T);
                vrf_input.extend_from_slice(entropy_3.as_slice());
                vrf_input.push(ticket.attempt);
                vrf_input
            }
            SlotSealer::BandersnatchPubKeys(key) => {
                if key != &self.curr_author_bandersnatch_key {
                    return Err(BlockImportError::InvalidFallbackAuthorKey);
                }
                let mut vrf_input = Vec::with_capacity(X_F.len() + entropy_3.len());
                vrf_input.extend_from_slice(X_F);
                vrf_input.extend_from_slice(entropy_3.as_slice());
                vrf_input
            }
        };
        let aux_data = self.curr_block.header.header_data.encode()?;

        VrfVerifier::verify_vrf(
            &vrf_input,
            &aux_data,
            block_seal,
            &self.curr_author_bandersnatch_key,
        )?;
        Ok(())
    }

    fn verify_vrf_output(&self) -> Result<(), BlockImportError> {
        let block_seal_output_hash = self.curr_block.header.block_seal.output_hash();

        let mut vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
        vrf_input.extend_from_slice(X_E);
        vrf_input.extend_from_slice(block_seal_output_hash.as_slice());
        let aux_data = vec![]; // no message signed

        VrfVerifier::verify_vrf(
            &vrf_input,
            &aux_data,
            &self.curr_block.header.header_data.vrf_signature,
            &self.curr_author_bandersnatch_key,
        )?;
        Ok(())
    }

    async fn run_state_transition(&self) -> Result<Hash32, BlockImportError> {
        let executor = BlockExecutor::new(self.state_manager.clone());
        let output = executor.run_state_transition(&self.curr_block).await?;
        executor
            .accumulate_entropy(&self.curr_block.header.vrf_signature())
            .await?;
        executor
            .append_block_history(
                self.curr_block.header.hash()?,
                output.accumulate_root,
                output.reported_packages,
            )
            .await?;
        // TODO: additional validation on output
        self.state_manager.commit_dirty_cache().await?;
        Ok(self.state_manager.merkle_root())
    }
}
