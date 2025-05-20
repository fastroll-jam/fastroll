use crate::{
    roles::{
        author::author_block_seal_is_valid,
        executor::{BlockExecutionError, BlockExecutor},
    },
    utils::spawn_timed,
};
use fr_block::types::{
    block::{Block, BlockHeader, BlockHeaderError},
    extrinsics::ExtrinsicsError,
};
use fr_codec::prelude::*;
use fr_common::{Hash32, HASH_SIZE, X_E, X_F, X_T};
use fr_crypto::{
    error::CryptoError, traits::VrfSignature, types::BandersnatchPubKey,
    vrf::bandersnatch_vrf::VrfVerifier,
};
use fr_extrinsics::validation::{
    assurances::AssurancesXtValidator, disputes::DisputesXtValidator, error::XtError,
    guarantees::GuaranteesXtValidator, preimages::PreimagesXtValidator,
    tickets::TicketsXtValidator,
};
use fr_state::{
    error::StateManagerError,
    types::{SlotSealer, Timeslot},
};
use fr_storage::NodeStorage;
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

pub struct BlockImporter;
impl BlockImporter {
    pub async fn import_block(
        storage: Arc<NodeStorage>,
        block: Block,
    ) -> Result<Hash32, BlockImportError> {
        tracing::info!(
            "Block imported. Parent hash: {}",
            &block.header.data.parent_hash
        );
        Self::validate_block(storage, block).await
    }

    async fn validate_block(
        storage: Arc<NodeStorage>,
        block: Block,
    ) -> Result<Hash32, BlockImportError> {
        // Validate Xts
        Self::validate_xts(&storage, &block).await?;
        // Validate header fields (prior to STF)
        Self::validate_block_header_prior_stf(&storage, &block)?;
        // Re-execute STF
        let post_state_root = Self::run_state_transition(&storage, &block).await?;
        // Validate header fields (post STF)
        Self::validate_block_header_post_stf(&storage, &block).await?;
        Ok(post_state_root)
    }

    /// Note: Currently, each STF validates Xt types as well.
    async fn validate_xts(storage: &NodeStorage, block: &Block) -> Result<(), BlockImportError> {
        let prior_timeslot = storage.state_manager().get_timeslot_clean().await?;
        let curr_timeslot_index = block.header.timeslot_index();

        // Clone necessary data to spawn async tasks
        let parent_hash = block.header.parent_hash().clone();
        let tickets = block.extrinsics.tickets.clone();
        let preimages = block.extrinsics.preimages.clone();
        let guarantees = block.extrinsics.guarantees.clone();
        let assurances = block.extrinsics.assurances.clone();
        let disputes = block.extrinsics.disputes.clone();

        let tickets_validator = TicketsXtValidator::new(storage.state_manager());
        let preimages_validator = PreimagesXtValidator::new(storage.state_manager());
        let guarantees_validator = GuaranteesXtValidator::new(storage.state_manager());
        let assurances_validator = AssurancesXtValidator::new(storage.state_manager());
        let disputes_validator = DisputesXtValidator::new(storage.state_manager());

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

    fn validate_block_header_prior_stf(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<(), BlockImportError> {
        let best_header = storage.header_db().get_best_header();
        Self::validate_parent_hash(&best_header, block)?;
        Self::validate_timeslot_index(&best_header, block)?;
        // self.validate_prior_state_root()?; // TODO: impl
        Self::validate_xt_hash(block)?;
        Ok(())
    }

    /// Gets posterior state values required for header signatures validation
    async fn get_post_states(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<(SlotSealer, BandersnatchPubKey, Hash32), BlockImportError> {
        let curr_safrole = storage.state_manager().get_safrole().await?;
        let curr_timeslot = Timeslot::new(block.header.timeslot_index());
        let curr_slot_sealer = curr_safrole.slot_sealers.get_slot_sealer(&curr_timeslot);

        let curr_active_set = storage.state_manager().get_active_set().await?;
        let curr_author_index = block.header.author_index();
        let curr_author_bandersnatch_key = curr_active_set
            .get_validator_bandersnatch_key(curr_author_index)
            .ok_or(BlockImportError::InvalidAuthorIndex)?;

        let curr_epoch_entropy = storage.state_manager().get_epoch_entropy().await?;
        let curr_entropy_3 = curr_epoch_entropy.third_history();

        Ok((
            curr_slot_sealer,
            curr_author_bandersnatch_key.clone(),
            curr_entropy_3.clone(),
        ))
    }

    async fn validate_block_header_post_stf(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<(), BlockImportError> {
        let (curr_slot_sealer, curr_author_bandersnatch_key, curr_entropy_3) =
            Self::get_post_states(storage, block).await?;

        Self::verify_block_seal(
            block,
            &curr_slot_sealer,
            &curr_author_bandersnatch_key,
            &curr_entropy_3,
        )?;
        Self::verify_vrf_output(block, &curr_author_bandersnatch_key)?;
        // TODO: Check header markers
        Ok(())
    }

    fn validate_parent_hash(
        best_header: &BlockHeader,
        block: &Block,
    ) -> Result<(), BlockImportError> {
        if block.header.parent_hash() != &best_header.hash()? {
            return Err(BlockImportError::InvalidParentHash);
        };
        Ok(())
    }

    fn validate_timeslot_index(
        best_header: &BlockHeader,
        block: &Block,
    ) -> Result<(), BlockImportError> {
        let current_timeslot_index = block.header.timeslot_index();
        if current_timeslot_index <= best_header.timeslot_index() {
            return Err(BlockImportError::InvalidTimeslot);
        }
        if Timeslot::new(current_timeslot_index).is_in_future() {
            return Err(BlockImportError::TimeslotInFuture);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn validate_prior_state_root() -> Result<(), BlockImportError> {
        unimplemented!()
    }

    fn validate_xt_hash(block: &Block) -> Result<(), BlockImportError> {
        if block.header.extrinsic_hash() != &block.extrinsics.hash()? {
            return Err(BlockImportError::InvalidXtHash);
        }
        Ok(())
    }

    fn verify_block_seal(
        block: &Block,
        curr_slot_sealer: &SlotSealer,
        curr_author_bandersnatch_key: &BandersnatchPubKey,
        curr_entropy_3: &Hash32,
    ) -> Result<(), BlockImportError> {
        let block_seal = &block.header.block_seal;

        let vrf_input = match curr_slot_sealer {
            SlotSealer::Ticket(ticket) => {
                if !author_block_seal_is_valid(block_seal, ticket) {
                    return Err(BlockImportError::InvalidBlockSealOutput);
                }
                let mut vrf_input = Vec::with_capacity(X_T.len() + curr_entropy_3.len() + 1);
                vrf_input.extend_from_slice(X_T);
                vrf_input.extend_from_slice(curr_entropy_3.as_slice());
                vrf_input.push(ticket.attempt);
                vrf_input
            }
            SlotSealer::BandersnatchPubKeys(key) => {
                if key != curr_author_bandersnatch_key {
                    return Err(BlockImportError::InvalidFallbackAuthorKey);
                }
                let mut vrf_input = Vec::with_capacity(X_F.len() + curr_entropy_3.len());
                vrf_input.extend_from_slice(X_F);
                vrf_input.extend_from_slice(curr_entropy_3.as_slice());
                vrf_input
            }
        };
        let aux_data = block.header.data.encode()?;

        VrfVerifier::verify_vrf(
            &vrf_input,
            &aux_data,
            block_seal,
            curr_author_bandersnatch_key,
        )?;
        Ok(())
    }

    fn verify_vrf_output(
        block: &Block,
        curr_author_bandersnatch_key: &BandersnatchPubKey,
    ) -> Result<(), BlockImportError> {
        let block_seal_output_hash = block.header.block_seal.output_hash();

        let mut vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
        vrf_input.extend_from_slice(X_E);
        vrf_input.extend_from_slice(block_seal_output_hash.as_slice());
        let aux_data = vec![]; // no message signed

        VrfVerifier::verify_vrf(
            &vrf_input,
            &aux_data,
            &block.header.data.vrf_signature,
            curr_author_bandersnatch_key,
        )?;
        Ok(())
    }

    async fn run_state_transition(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<Hash32, BlockImportError> {
        let output = BlockExecutor::run_state_transition(storage, block).await?;
        BlockExecutor::accumulate_entropy(storage, &block.header.vrf_signature()).await?;
        BlockExecutor::append_block_history(
            storage,
            block.header.hash()?,
            output.accumulate_root,
            output.reported_packages,
        )
        .await?;
        // TODO: additional validation on output
        storage.state_manager().commit_dirty_cache().await?;
        Ok(storage.state_manager().merkle_root())
    }
}
