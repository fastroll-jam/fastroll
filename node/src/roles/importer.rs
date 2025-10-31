use crate::{
    roles::{
        author::validate_author_block_seal,
        executor::{BlockExecutionError, BlockExecutionHeaderMarkers, BlockExecutor},
    },
    utils::spawn_timed,
};
use fr_block::{
    header_db::BlockHeaderDBError,
    post_state_root_db::{PostStateRootDB, PostStateRootDbError},
    types::{
        block::{Block, BlockHeader, BlockHeaderError},
        extrinsics::ExtrinsicsError,
    },
};
use fr_codec::prelude::*;
use fr_common::{ByteEncodable, EntropyHash, StateRoot, HASH_SIZE, X_E, X_F, X_T};
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
    manager::StateCommitArtifact,
    types::{SlotSealer, Timeslot},
};
use fr_storage::node_storage::NodeStorage;
use fr_transition::state::services::AccountStateChanges;
use std::sync::Arc;
use thiserror::Error;
use tokio::{sync::mpsc, try_join};
use tracing::{instrument, Span};

#[derive(Debug, Error)]
pub enum BlockImportError {
    #[error("Block header contains invalid xt hash. Found in block: {header_value}, calculated: {calculated}"
    )]
    InvalidXtHash {
        header_value: String,
        calculated: String,
    },
    #[error("Block header contains invalid author index")]
    InvalidAuthorIndex,
    #[error("Block header is sealed with invalid fallback key. Reserved slot sealer key: {slot_sealer_key}, actual author key: {author_key}"
    )]
    InvalidFallbackAuthorKey {
        slot_sealer_key: String,
        author_key: String,
    },
    #[error("Block header seal doesn't match the ticket")]
    InvalidBlockSealOutput,
    #[error("Block header contains invalid parent hash. Parent hash: {0}, Best header hash: {1}")]
    InvalidParentHash(String, String),
    #[error("Block header contains timeslot that is later than the current system time")]
    TimeslotInFuture,
    #[error("Block header contains timeslot earlier than the parent header")]
    InvalidTimeslot,
    #[error("Block header contains invalid prior state root")]
    InvalidPriorStateRoot,
    #[error(
        "Post state root of the parent block is not found from the PostStateRootDB (header={0})"
    )]
    PriorStateRootNotFound(String),
    #[error("Block header contains invalid epoch marker")]
    InvalidEpochMarker,
    #[error("Block header contains invalid winning tickets marker")]
    InvalidWinningTicketsMarker,
    #[error("Block header contains invalid offenders marker")]
    InvalidOffendersMarker,
    #[error("XtError: {0}")]
    XtError(#[from] XtError),
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("PostStateRootDB: {0}")]
    PostStateRootDBError(#[from] PostStateRootDbError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockExecutionError: {0}")]
    BlockExecutionError(#[from] BlockExecutionError),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[derive(Clone, Copy)]
pub enum BlockCommitMode {
    /// Processes the block and immediately commit the block into DBs, finalizing the block.
    Immediate,
    /// Processes the block and produces DB write set for later commitment on block finalization.
    StageOnly,
}

pub struct BlockImportOutput {
    /// The new state root after the block import.
    pub post_state_root: StateRoot,
    /// The account state change set.
    pub account_state_changes: AccountStateChanges,
    /// The optional export of state commit artifact; only included in `StageOnly` block commit mode.
    pub state_commit_artifact: Option<StateCommitArtifact>,
}

pub struct BlockImporter;
impl BlockImporter {
    pub async fn run_block_importer(
        storage: Arc<NodeStorage>,
        mut block_import_mpsc_recv: mpsc::Receiver<Block>,
    ) {
        while let Some(block) = block_import_mpsc_recv.recv().await {
            let header_hash = match block.header.hash() {
                Ok(hash) => hash,
                Err(e) => {
                    tracing::error!("Block Import Error (Header hashing failed): {e}");
                    continue;
                }
            };
            let timeslot_index = block.header.timeslot_index();
            match Self::import_block(
                storage.clone(),
                block,
                false,
                false,
                BlockCommitMode::Immediate,
            )
            .await
            {
                Ok(output) => {
                    tracing::info!("✅ Block validated ({header_hash}) (slot: {timeslot_index})");
                    if let Err(e) = storage
                        .post_state_root_db()
                        .set_post_state_root(&header_hash, output.post_state_root.clone())
                        .await
                    {
                        tracing::error!("Failed to set post state root of the block: {e:?}");
                    }
                }
                Err(e) => {
                    tracing::error!("Invalid block: {e}");
                    // Rollback uncommitted state changes
                    storage.state_manager().rollback_dirty_cache();
                }
            }
        }
    }

    pub async fn import_block(
        storage: Arc<NodeStorage>,
        block: Block,
        is_first_fuzz_block: bool,
        with_ancestors: bool,
        block_commit_mode: BlockCommitMode,
    ) -> Result<BlockImportOutput, BlockImportError> {
        tracing::info!(
            "📥 Block imported (slot={})(header_hash={})",
            block.header.timeslot_index(),
            &block.header.hash()?,
        );
        let block_import_output = Self::validate_block(
            storage.clone(),
            &block,
            is_first_fuzz_block,
            with_ancestors,
            block_commit_mode,
        )
        .await?;

        // Store the block header to the block header DB & ancestor set
        let header_db = storage.header_db();
        header_db
            .insert_header(block.header.hash()?, block.header)
            .await?;

        Ok(block_import_output)
    }

    async fn validate_block(
        storage: Arc<NodeStorage>,
        block: &Block,
        is_first_fuzz_block: bool,
        with_ancestors: bool,
        block_commit_mode: BlockCommitMode,
    ) -> Result<BlockImportOutput, BlockImportError> {
        if block.is_genesis() {
            // Skip validation for the genesis block
            let output =
                Self::run_state_transition(&storage, block, with_ancestors, block_commit_mode)
                    .await?;
            return Ok(output);
        }

        // Validate header fields (prior to STF)
        Self::validate_block_header_prior_stf(&storage, block, is_first_fuzz_block).await?;
        // Re-execute STF
        let output =
            Self::run_state_transition(&storage, block, with_ancestors, block_commit_mode).await?;

        // Set best header
        if matches!(block_commit_mode, BlockCommitMode::Immediate) {
            storage.header_db().set_best_header(block.header.clone());
        }
        Ok(output)
    }

    /// Note: Currently, each STF validates Xt types as well. Up-front Xt validations might work
    /// incorrectly, since some validation rules need to refer to partially transitioned state.
    #[allow(dead_code)]
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

        tracing::debug!("tickets_xt count={}", tickets.len());
        tracing::debug!("preimages_xt count={}", preimages.len());
        tracing::debug!("guarantees_xt count={}", guarantees.len());
        tracing::debug!("assurances_xt count={}", assurances.len());
        tracing::debug!(
            "disputes_xt count: verdicts={}, culprits={}, faults={}",
            disputes.verdicts.len(),
            disputes.culprits.len(),
            disputes.faults.len(),
        );

        let tickets_validator = TicketsXtValidator::new(storage.state_manager());
        let preimages_validator = PreimagesXtValidator::new(storage.state_manager());
        let guarantees_validator =
            GuaranteesXtValidator::new(storage.state_manager(), storage.header_db(), false);
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

        let (t_res, p_res, g_res, a_res, d_res) = try_join!(
            tickets_jh,
            preimages_jh,
            guarantees_jh,
            assurances_jh,
            disputes_jh
        )?;
        t_res?;
        p_res?;
        g_res?;
        a_res?;
        d_res?;
        Ok(())
    }

    #[instrument(level = "debug", skip_all, name = "val_header_1")]
    async fn validate_block_header_prior_stf(
        storage: &NodeStorage,
        block: &Block,
        is_first_fuzz_block: bool,
    ) -> Result<(), BlockImportError> {
        let best_header = storage.header_db().get_best_header();
        // Note: Skips timeslot validation if this function is run by fuzz target
        #[cfg(not(feature = "fuzz"))]
        Self::validate_timeslot_index(&best_header, block)?;

        // Note: Skips validation of header fields related to the prior block if it is the first block for fuzzing
        // if !is_first_fuzz_block {
        //     Self::validate_parent_hash(&best_header, block)?;
        //     Self::validate_prior_state_root(storage.post_state_root_db(), &block.header).await?;
        // }
        Self::validate_xt_hash(block)?;
        Ok(())
    }

    /// Gets posterior state values required for header signatures validation.
    ///
    /// Note: this method is called after running the initial STFs.
    #[instrument(level = "debug", skip_all, name = "get_post_state")]
    async fn get_post_states_for_header_validation(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<(SlotSealer, BandersnatchPubKey, EntropyHash), BlockImportError> {
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

    #[instrument(level = "debug", skip_all, name = "val_header_2")]
    async fn validate_block_header_post_safrole(
        storage: &NodeStorage,
        block: &Block,
        markers: BlockExecutionHeaderMarkers,
    ) -> Result<(), BlockImportError> {
        let block_cloned = block.clone();
        let (curr_slot_sealer, curr_author_bandersnatch_key, curr_entropy_3) =
            Self::get_post_states_for_header_validation(storage, block).await?;

        let curr_span = Span::current();
        tokio::task::spawn_blocking(move || -> Result<(), BlockImportError> {
            let (seal_result, vrf_result) = rayon::join(
                || {
                    curr_span.clone().in_scope(|| {
                        Self::verify_block_seal(
                            &block_cloned,
                            &curr_slot_sealer,
                            &curr_author_bandersnatch_key,
                            &curr_entropy_3,
                        )
                    })
                },
                || {
                    curr_span.in_scope(|| {
                        Self::verify_vrf_output(&block_cloned, &curr_author_bandersnatch_key)
                    })
                },
            );
            seal_result?;
            vrf_result?;
            Ok(())
        })
        .await??;

        Self::validate_header_markers(block, markers)?;
        Ok(())
    }

    fn validate_parent_hash(
        best_header: &BlockHeader,
        block: &Block,
    ) -> Result<(), BlockImportError> {
        let parent_hash = block.header.parent_hash();
        let best_header_hash = best_header.hash()?;
        if parent_hash != &best_header_hash {
            return Err(BlockImportError::InvalidParentHash(
                parent_hash.to_hex(),
                best_header_hash.to_hex(),
            ));
        };
        Ok(())
    }

    #[cfg(not(feature = "fuzz"))]
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

    async fn validate_prior_state_root(
        post_state_root_db: Arc<PostStateRootDB>,
        block_header: &BlockHeader,
    ) -> Result<(), BlockImportError> {
        // Get post state root of the parent block (prior state root)
        let Some(prior_state_root) = post_state_root_db
            .get_post_state_root(block_header.parent_hash())
            .await?
        else {
            return Err(BlockImportError::PriorStateRootNotFound(
                block_header.parent_hash().encode_hex(),
            ));
        };

        if prior_state_root != block_header.data.prior_state_root {
            return Err(BlockImportError::InvalidPriorStateRoot);
        }
        Ok(())
    }

    fn validate_xt_hash(block: &Block) -> Result<(), BlockImportError> {
        if block.header.extrinsic_hash() != &block.extrinsics.hash()? {
            return Err(BlockImportError::InvalidXtHash {
                header_value: block.header.extrinsic_hash().encode_hex(),
                calculated: block.extrinsics.hash()?.encode_hex(),
            });
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all, name = "verify_seal")]
    fn verify_block_seal(
        block: &Block,
        curr_slot_sealer: &SlotSealer,
        curr_author_bandersnatch_key: &BandersnatchPubKey,
        curr_entropy_3: &EntropyHash,
    ) -> Result<(), BlockImportError> {
        let block_seal = &block.header.block_seal;

        let vrf_input = match curr_slot_sealer {
            SlotSealer::Ticket(ticket) => {
                validate_author_block_seal(block_seal, ticket)
                    .map_err(|_| BlockImportError::InvalidBlockSealOutput)?;
                let mut vrf_input = Vec::with_capacity(X_T.len() + HASH_SIZE + 1);
                vrf_input.extend_from_slice(X_T);
                vrf_input.extend_from_slice(curr_entropy_3.as_slice());
                vrf_input.push(ticket.attempt);
                vrf_input
            }
            SlotSealer::BandersnatchPubKeys(key) => {
                if key != curr_author_bandersnatch_key {
                    return Err(BlockImportError::InvalidFallbackAuthorKey {
                        slot_sealer_key: key.to_hex(),
                        author_key: curr_author_bandersnatch_key.to_hex(),
                    });
                }
                let mut vrf_input = Vec::with_capacity(X_F.len() + HASH_SIZE);
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

    #[instrument(level = "debug", skip_all, name = "verify_vrf")]
    fn verify_vrf_output(
        block: &Block,
        curr_author_bandersnatch_key: &BandersnatchPubKey,
    ) -> Result<(), BlockImportError> {
        let block_seal_output_hash = block.header.block_seal.output_hash()?;

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

    #[instrument(level = "debug", skip_all, name = "val_markers")]
    fn validate_header_markers(
        block: &Block,
        expected_markers: BlockExecutionHeaderMarkers,
    ) -> Result<(), BlockImportError> {
        // Validate epoch marker
        if block.header.epoch_marker() != expected_markers.safrole_markers.epoch_marker.as_ref() {
            return Err(BlockImportError::InvalidEpochMarker);
        }
        // Validate winning-tickets marker
        if block.header.winning_tickets_marker()
            != expected_markers
                .safrole_markers
                .winning_tickets_marker
                .as_ref()
        {
            return Err(BlockImportError::InvalidWinningTicketsMarker);
        }
        // Validate offenders marker
        if block.header.offenders_marker() != expected_markers.offenders_marker.items.as_slice() {
            return Err(BlockImportError::InvalidOffendersMarker);
        }
        Ok(())
    }

    #[instrument(level = "info", skip_all, name = "stf")]
    async fn run_state_transition(
        storage: &NodeStorage,
        block: &Block,
        with_ancestors: bool,
        block_commit_mode: BlockCommitMode,
    ) -> Result<BlockImportOutput, BlockImportError> {
        let account_state_changes = if block.is_genesis() {
            let output = BlockExecutor::run_genesis_state_transition(storage, block).await?;
            BlockExecutor::append_beefy_belt_and_block_history(
                storage,
                output.accumulate_root,
                block.header.hash()?,
                output.reported_packages,
            )
            .await?;
            output.account_state_changes
        } else {
            // STF phase #1
            let markers =
                BlockExecutor::run_state_transition_pre_header_commitment(storage, block).await?;

            // Validate remaining header fields (post Safrole STF)
            Self::validate_block_header_post_safrole(storage, block, markers).await?;

            // STF phase #2
            let output = BlockExecutor::run_state_transition_post_header_commitment(
                storage,
                block,
                with_ancestors,
            )
            .await?;

            // STF phase #3
            BlockExecutor::append_beefy_belt_and_block_history(
                storage,
                output.accumulate_root,
                block.header.hash()?,
                output.reported_packages,
            )
            .await?;
            output.account_state_changes
        };

        let mut state_commit_artifact = None;
        let post_state_root = match block_commit_mode {
            BlockCommitMode::Immediate => {
                storage.state_manager().commit_dirty_cache().await?;
                storage.state_manager().merkle_root().await?
            }
            BlockCommitMode::StageOnly => {
                if let Some(artifact) = storage.state_manager().prepare_dirty_cache_commit().await?
                {
                    let root = artifact.state_root().clone();
                    state_commit_artifact = Some(artifact);
                    root
                } else {
                    // State is unchanged
                    let root = storage.state_manager().merkle_root().await?;
                    storage.state_manager().rollback_dirty_cache();
                    root
                }
            }
        };

        Ok(BlockImportOutput {
            post_state_root,
            account_state_changes,
            state_commit_artifact,
        })
    }
}
