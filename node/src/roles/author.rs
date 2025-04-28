//! Block author actor

use crate::roles::executor::{BlockExecutionError, BlockExecutionOutput, BlockExecutor};
use rjam_block::{
    header_db::{BlockHeaderDB, BlockHeaderDBError},
    types::{
        block::{Block, BlockHeader, BlockHeaderData, BlockHeaderError, BlockSeal, VrfSig},
        extrinsics::Extrinsics,
    },
};
use rjam_codec::prelude::*;
use rjam_common::{
    ticket::Ticket, ByteArray, CommonTypeError, Hash32, ValidatorIndex, HASH_SIZE, X_E, X_F, X_T,
};
use rjam_crypto::{
    traits::VrfSignature, types::BandersnatchSecretKey, vrf::bandersnatch_vrf::VrfProver,
};
use rjam_state::{error::StateManagerError, manager::StateManager, types::SlotSealer};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockAuthorError {
    #[error("Block seal output hash doesn't match ticket proof output hash")]
    InvalidBlockSealOutput,
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("BlockExecutionError: {0}")]
    BlockExecutionError(#[from] BlockExecutionError),
}

#[allow(dead_code)]
pub struct BlockAuthor {
    state_manager: Arc<StateManager>,
    header_db: Arc<BlockHeaderDB>,
    best_header: BlockHeader,
    author_index: ValidatorIndex,
}

#[allow(dead_code)]
impl BlockAuthor {
    pub fn new(
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        best_header: BlockHeader,
        author_index: ValidatorIndex,
    ) -> Self {
        Self {
            state_manager,
            header_db,
            best_header,
            author_index,
        }
    }

    pub async fn author_block(&mut self) -> Result<Block, BlockAuthorError> {
        let extrinsics = self.collect_extrinsics()?;
        self.prelude()?;

        // Construct a block with some header fields missing
        let staging_header = self
            .header_db
            .get_staging_header()
            .expect("Staging header should be initialized");

        let mut new_block = Block {
            header: staging_header,
            extrinsics,
        };

        // STF phase #1
        let stf_output = self.run_initial_state_transition(&new_block).await?;
        let vrf_sig = self.epilogue(stf_output.clone()).await?;
        self.seal_block_header().await?;

        // Commit block header
        let new_header_hash = self.commit_header().await?;

        self.finalize_block(&new_header_hash, &mut new_block)
            .await?;

        // STF phase #2
        self.run_final_state_transition(new_header_hash, &vrf_sig, stf_output)
            .await?;

        // Commit the state transitions
        // TODO: Defer more STF runs to post-header-commit.
        // Note: Also some STFs can be run asynchronously after committing the header.
        self.state_manager.commit_dirty_cache().await?;
        tracing::info!("Post State Root: {}", self.state_manager.merkle_root());

        Ok(new_block)
    }

    fn collect_extrinsics(&mut self) -> Result<Extrinsics, BlockAuthorError> {
        // FIXME: Actually collect from the Xt store
        let xts = Extrinsics::default();
        self.header_db.set_extrinsic_hash(&xts)?;
        Ok(xts)
    }

    fn load_bandersnatch_secret_key() -> BandersnatchSecretKey {
        // FIXME: Actually load sk from keystore
        BandersnatchSecretKey(ByteArray::default())
    }

    /// Sets header fields required for running STFs in advance.
    fn prelude(&mut self) -> Result<(), BlockAuthorError> {
        let parent_hash = self.best_header.hash()?;
        tracing::info!("Parent header hash: {}", parent_hash);
        let prior_state_root = self.state_manager.merkle_root();
        tracing::info!("Prior state root: {}", prior_state_root);

        self.header_db.set_parent_state_root(prior_state_root)?;
        self.header_db.set_block_author_index(self.author_index)?;
        self.header_db.set_timeslot()?;

        Ok(())
    }

    async fn run_initial_state_transition(
        &self,
        block: &Block,
    ) -> Result<BlockExecutionOutput, BlockAuthorError> {
        let executor = BlockExecutor::new(self.state_manager.clone());
        Ok(executor.run_state_transition(block).await?)
    }

    /// Sets missing header fields with contexts produced during the STF run.
    async fn epilogue(
        &mut self,
        stf_output: BlockExecutionOutput,
    ) -> Result<VrfSig, BlockAuthorError> {
        let author_sk = Self::load_bandersnatch_secret_key();

        // Sign VRF
        let curr_timeslot = self.state_manager.get_timeslot().await?;
        let curr_slot_sealer = self
            .state_manager
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(&curr_timeslot);
        let epoch_entropy = self.state_manager.get_epoch_entropy().await?;
        let curr_entropy_3 = epoch_entropy.third_history();
        let vrf_sig =
            sign_entropy_source_vrf_signature(&curr_slot_sealer, curr_entropy_3, &author_sk)?;
        self.header_db.set_vrf_signature(&vrf_sig)?;

        // Set header markers
        self.header_db
            .set_offenders_marker(&stf_output.offenders_marker)?;
        if let Some(epoch_marker) = stf_output.safrole_markers.epoch_marker.as_ref() {
            self.header_db.set_epoch_marker(&epoch_marker)?;
        }
        if let Some(winning_tickets_marker) =
            stf_output.safrole_markers.winning_tickets_marker.as_ref()
        {
            self.header_db
                .set_winning_tickets_marker(&winning_tickets_marker)?;
        }

        Ok(vrf_sig)
    }

    /// Seal the block header
    async fn seal_block_header(&mut self) -> Result<(), BlockAuthorError> {
        let author_sk = Self::load_bandersnatch_secret_key();

        let staging_header_data = self
            .header_db
            .get_staging_header()
            .expect("Staging header should be initialized")
            .header_data;
        // FIXME (duplicate code): `SlotSealer` and `EpochEntropy` are already loaded in `epilogue`
        let curr_timeslot = self.state_manager.get_timeslot().await?;
        let curr_slot_sealer = self
            .state_manager
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(&curr_timeslot);
        let epoch_entropy = self.state_manager.get_epoch_entropy().await?;
        let curr_entropy_3 = epoch_entropy.third_history();

        let seal = match curr_slot_sealer {
            SlotSealer::Ticket(ticket) => {
                sign_block_seal(staging_header_data, &ticket, curr_entropy_3, &author_sk)?
            }
            SlotSealer::BandersnatchPubKeys(_key) => {
                sign_fallback_block_seal(staging_header_data, curr_entropy_3, &author_sk)?
            }
        };
        self.header_db.set_block_seal(&seal)?;

        Ok(())
    }

    async fn commit_header(&mut self) -> Result<Hash32, BlockAuthorError> {
        Ok(self.header_db.commit_staging_header().await?)
    }

    async fn finalize_block(
        &self,
        new_header_hash: &Hash32,
        new_block: &mut Block,
    ) -> Result<(), BlockAuthorError> {
        let new_header = self
            .header_db
            .get_header(new_header_hash)
            .await?
            .expect("New header should already be committed");
        // update the block header with the final header state
        new_block.header = new_header;
        tracing::info!("New block created. Header hash: {new_header_hash}");
        Ok(())
    }

    /// Runs the final two STFs.
    /// 1. Accumulates epoch entropy (`η0′` --> `η0′`)
    /// 2. Appends a new block history entry (`β†` --> `β′`)
    async fn run_final_state_transition(
        &self,
        new_header_hash: Hash32,
        vrf_sig: &VrfSig,
        stf_output: BlockExecutionOutput,
    ) -> Result<(), BlockAuthorError> {
        let executor = BlockExecutor::new(self.state_manager.clone());
        executor.accumulate_entropy(&vrf_sig).await?;
        executor
            .append_block_history(
                new_header_hash,
                stf_output.accumulate_root,
                stf_output.reported_packages,
            )
            .await?;
        Ok(())
    }
}

/// Verifies output hash of the block seal matches the ticket used for the author selection.
pub fn author_block_seal_is_valid(seal: &BlockSeal, ticket: &Ticket) -> bool {
    let seal_output_hash = seal.output_hash();
    let ticket_output_hash = ticket.id.clone();
    seal_output_hash == ticket_output_hash
}

/// Seals the block header as the block author, in regular (ticket) mode.
///
/// Note: This signing should be done ***after*** signing the VRF signature of the header.
pub fn sign_block_seal(
    header_data: BlockHeaderData,
    used_ticket: &Ticket,
    curr_entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockAuthorError> {
    let prover = VrfProver::from_secret_key(secret_key);
    let mut vrf_input = Vec::with_capacity(X_T.len() + curr_entropy_3.len() + 1);
    vrf_input.extend_from_slice(X_T);
    vrf_input.extend_from_slice(curr_entropy_3.as_slice());
    vrf_input.push(used_ticket.attempt);
    let aux_data = header_data.encode()?;
    let seal = prover.sign_vrf(&vrf_input, &aux_data);

    if !author_block_seal_is_valid(&seal, used_ticket) {
        return Err(BlockAuthorError::InvalidBlockSealOutput);
    }
    Ok(seal)
}

/// Seals the block header as the block author, in fallback mode.
///
/// Note: This signing should be done ***after*** signing the VRF signature of the header.
pub fn sign_fallback_block_seal(
    header_data: BlockHeaderData,
    curr_entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<BlockSeal, BlockAuthorError> {
    let prover = VrfProver::from_secret_key(secret_key);
    let mut vrf_input = Vec::with_capacity(X_F.len() + curr_entropy_3.len());
    vrf_input.extend_from_slice(X_F);
    vrf_input.extend_from_slice(curr_entropy_3.as_slice());
    let aux_data = header_data.encode()?;
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}

/// Produces VRF signature as the block author.
/// This is later used as the epochal entropy source.
///
/// According to the GP, the block seal's output hash is used to sign the entropy source vrf signature.
/// However, since the VRF signature must be produced prior to the block seal,
/// this function uses VRF output hash values which are equivalent to the seal output.
///
/// In regular (ticket) mode, this is the ticket id used in the contest.
/// In fallback mode, this can be produced by conducting the same signing for the block sealing with
/// the aux data (message) omitted.
///
/// Note: The aux data (message) doesn't affect the VRF output hash value.
pub fn sign_entropy_source_vrf_signature(
    slot_sealer: &SlotSealer,
    curr_entropy_3: &Hash32,
    secret_key: &BandersnatchSecretKey,
) -> Result<VrfSig, BlockAuthorError> {
    let prover = VrfProver::from_secret_key(secret_key);

    // This value is equivalent to `Y` hash output of the block seal.
    let seal_output_hash = match slot_sealer {
        SlotSealer::Ticket(ticket) => ticket.id.clone(),
        SlotSealer::BandersnatchPubKeys(_key) => {
            // Sign with an empty aux data (message) to get the output hash
            let mut fallback_seal_vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
            fallback_seal_vrf_input.extend_from_slice(X_F);
            fallback_seal_vrf_input.extend_from_slice(curr_entropy_3.as_slice());
            let aux_data = vec![];
            prover
                .sign_vrf(&fallback_seal_vrf_input, &aux_data)
                .output_hash()
        }
    };

    let mut vrf_input = Vec::with_capacity(X_E.len() + HASH_SIZE);
    vrf_input.extend_from_slice(X_E);
    vrf_input.extend_from_slice(seal_output_hash.as_slice());
    let aux_data = vec![]; // no message to sign
    Ok(prover.sign_vrf(&vrf_input, &aux_data))
}
