//! Block author role
use crate::{
    keystore::load_author_secret_key,
    roles::executor::{BlockExecutionError, BlockExecutionOutput, BlockExecutor},
};
use fr_block::{
    header_db::BlockHeaderDBError,
    types::{
        block::{Block, BlockHeaderData, BlockHeaderError, BlockSeal, VrfSig},
        extrinsics::{Extrinsics, ExtrinsicsError},
    },
    xt_db::XtDBError,
};
use fr_clock::Clock;
use fr_codec::prelude::*;
use fr_common::{
    ticket::Ticket, ByteEncodable, CommonTypeError, Hash32, ValidatorIndex, HASH_SIZE, X_E, X_F,
    X_T,
};
use fr_crypto::{
    traits::VrfSignature,
    types::{BandersnatchPubKey, BandersnatchSecretKey},
    vrf::bandersnatch_vrf::VrfProver,
};
use fr_network::manager::LocalNodeInfo;
use fr_state::{error::StateManagerError, types::SlotSealer};
use fr_storage::node_storage::NodeStorage;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlockAuthorError {
    #[error("JamCodecError: {0}")]
    JamCodecError(#[from] JamCodecError),
    #[error("CommonTypeError: {0}")]
    CommonTypeError(#[from] CommonTypeError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("BlockHeaderDBError: {0}")]
    BlockHeaderDBError(#[from] BlockHeaderDBError),
    #[error("XtDBError: {0}")]
    XtDBError(#[from] XtDBError),
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
    #[error("BlockExecutionError: {0}")]
    BlockExecutionError(#[from] BlockExecutionError),
    #[error("Block seal output hash doesn't match ticket proof output hash")]
    InvalidBlockSealOutput,
    #[error("System time is before the JAM common era")]
    InvalidSysTime,
    #[error("Author key is not found from the keystore")]
    AuthorKeyNotFound,
}

struct AuthorInfo {
    /// Validator index of the author in the current `ActiveSet`.
    author_index: ValidatorIndex,
    /// The author's Bandersnatch secret key used for signing block seal and STF output.
    author_sk: BandersnatchSecretKey,
}

pub struct BlockAuthor {
    new_block: Block,
    author_info: AuthorInfo,
}

impl BlockAuthor {
    pub fn new(
        validator_index: ValidatorIndex,
        local_node_info: LocalNodeInfo,
    ) -> Result<Self, BlockAuthorError> {
        let author_pub_key = local_node_info.bandersnatch_key();
        let author_sk =
            load_author_secret_key(author_pub_key).ok_or(BlockAuthorError::AuthorKeyNotFound)?;
        Ok(Self {
            new_block: Block::default(),
            author_info: AuthorInfo {
                author_index: validator_index,
                author_sk,
            },
        })
    }

    /// Note: test-only
    pub fn new_for_fallback_test() -> Result<Self, BlockAuthorError> {
        // Hard-coded author info for tests
        let author_pub_key = BandersnatchPubKey::from_hex(
            "0xf16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d",
        )
        .expect("Invalid hexstring");
        let author_sk = load_author_secret_key(&author_pub_key).expect("Dev account should exist");
        let author_index = 5;

        Ok(Self {
            new_block: Block::default(),
            author_info: AuthorInfo {
                author_index,
                author_sk,
            },
        })
    }

    pub async fn author_block(
        &mut self,
        storage: Arc<NodeStorage>,
    ) -> Result<(Block, Hash32), BlockAuthorError> {
        let xt = Self::collect_extrinsics();
        let xt_hash = xt.hash()?;
        self.set_extrinsics(xt.clone(), xt_hash.clone())?;
        self.prelude(&storage)?;

        // STF phase #1
        let stf_output = self.run_initial_state_transition(&storage).await?;
        let vrf_sig = self.epilogue(&storage, stf_output.clone()).await?;
        self.seal_block_header(&storage).await?;

        // Commit block header and finalize block
        let new_header_hash = self.commit_header(&storage).await?;

        // STF phase #2
        self.run_final_state_transition(&storage, new_header_hash, &vrf_sig, stf_output)
            .await?;

        // Commit the state transitions
        // TODO: Defer more STF runs to post-header-commit.
        // Note: Also some STFs can be run asynchronously after committing the header.
        storage.state_manager().commit_dirty_cache().await?;
        let post_state_root = storage.state_manager().merkle_root();
        tracing::debug!("Post State Root: {}", &post_state_root);

        // Store extrinsics
        storage.xt_db().set_xt(&xt_hash, xt).await?;

        Ok((self.new_block.clone(), post_state_root))
    }

    /// Note: test-only
    pub async fn author_block_for_test(
        &mut self,
        storage: Arc<NodeStorage>,
    ) -> Result<(Block, Hash32), BlockAuthorError> {
        let xt = Self::collect_extrinsics();
        let xt_hash = xt.hash()?;
        self.set_extrinsics(xt.clone(), xt_hash.clone())?;
        self.prelude_for_test(&storage)?;
        let stf_output = self.run_initial_state_transition(&storage).await?;
        let vrf_sig = self.epilogue(&storage, stf_output.clone()).await?;
        self.seal_block_header(&storage).await?;
        let new_header_hash = self.commit_header(&storage).await?;
        self.run_final_state_transition(&storage, new_header_hash, &vrf_sig, stf_output)
            .await?;
        storage.state_manager().commit_dirty_cache().await?;
        let post_state_root = storage.state_manager().merkle_root();
        tracing::debug!("Post State Root: {}", &post_state_root);
        // Store extrinsics
        storage.xt_db().set_xt(&xt_hash, xt).await?;
        Ok((self.new_block.clone(), post_state_root))
    }

    fn collect_extrinsics() -> Extrinsics {
        // FIXME: Actually collect from the Xt store
        Extrinsics::default()
    }

    fn set_extrinsics(
        &mut self,
        xts: Extrinsics,
        xts_hash: Hash32,
    ) -> Result<(), BlockAuthorError> {
        self.new_block.extrinsics = xts;
        self.new_block.header.set_extrinsic_hash(xts_hash);
        Ok(())
    }

    /// Sets header fields required for running STFs in advance.
    fn prelude(&mut self, storage: &NodeStorage) -> Result<(), BlockAuthorError> {
        let parent_hash = storage.header_db().get_best_header().hash()?;
        tracing::debug!("Parent header hash: {}", &parent_hash);
        let prior_state_root = storage.state_manager().merkle_root();
        tracing::debug!("Prior state root: {}", &prior_state_root);

        self.new_block.header.set_parent_hash(parent_hash);
        self.new_block.header.set_prior_state_root(prior_state_root);
        self.new_block
            .header
            .set_author_index(self.author_info.author_index);
        self.new_block
            .header
            .set_timeslot(Clock::now_jam_timeslot().ok_or(BlockAuthorError::InvalidSysTime)?);

        Ok(())
    }

    /// Note: test-only
    fn prelude_for_test(&mut self, storage: &NodeStorage) -> Result<(), BlockAuthorError> {
        let parent_hash = storage.header_db().get_best_header().hash()?;
        tracing::debug!("Parent header hash: {}", &parent_hash);
        let prior_state_root = storage.state_manager().merkle_root();
        tracing::debug!("Prior state root: {}", &prior_state_root);
        self.new_block.header.set_parent_hash(parent_hash);
        self.new_block.header.set_prior_state_root(prior_state_root);
        self.new_block
            .header
            .set_author_index(self.author_info.author_index);
        // Uses hard-coded test-only timeslot value
        self.new_block.header.set_timeslot(12);
        Ok(())
    }

    async fn run_initial_state_transition(
        &self,
        storage: &NodeStorage,
    ) -> Result<BlockExecutionOutput, BlockAuthorError> {
        Ok(BlockExecutor::run_state_transition(storage, &self.new_block).await?)
    }

    /// Sets missing header fields with contexts produced during the STF run.
    async fn epilogue(
        &mut self,
        storage: &NodeStorage,
        stf_output: BlockExecutionOutput,
    ) -> Result<VrfSig, BlockAuthorError> {
        // Sign VRF
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let curr_slot_sealer = storage
            .state_manager()
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(&curr_timeslot);
        let epoch_entropy = storage.state_manager().get_epoch_entropy().await?;
        let curr_entropy_3 = epoch_entropy.third_history();
        let vrf_sig = sign_entropy_source_vrf_signature(
            &curr_slot_sealer,
            curr_entropy_3,
            &self.author_info.author_sk,
        )?;
        self.new_block.header.set_vrf_signature(vrf_sig.clone());

        // Set header markers
        self.new_block
            .header
            .set_offenders_marker(stf_output.offenders_marker);
        if let Some(epoch_marker) = stf_output.safrole_markers.epoch_marker {
            self.new_block.header.set_epoch_marker(epoch_marker);
        }
        if let Some(winning_tickets_marker) = stf_output.safrole_markers.winning_tickets_marker {
            self.new_block
                .header
                .set_winning_tickets_marker(winning_tickets_marker);
        }

        Ok(vrf_sig)
    }

    /// Seal the block header
    async fn seal_block_header(&mut self, storage: &NodeStorage) -> Result<(), BlockAuthorError> {
        let new_header_data = self.new_block.header.data.clone();
        // FIXME (duplicate code): `SlotSealer` and `EpochEntropy` are already loaded in `epilogue`
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let curr_slot_sealer = storage
            .state_manager()
            .get_safrole()
            .await?
            .slot_sealers
            .get_slot_sealer(&curr_timeslot);
        let epoch_entropy = storage.state_manager().get_epoch_entropy().await?;
        let curr_entropy_3 = epoch_entropy.third_history();

        let seal = match curr_slot_sealer {
            SlotSealer::Ticket(ticket) => sign_block_seal(
                new_header_data,
                &ticket,
                curr_entropy_3,
                &self.author_info.author_sk,
            )?,
            SlotSealer::BandersnatchPubKeys(_key) => sign_fallback_block_seal(
                new_header_data,
                curr_entropy_3,
                &self.author_info.author_sk,
            )?,
        };
        self.new_block.header.set_block_seal(seal);

        Ok(())
    }

    async fn commit_header(&mut self, storage: &NodeStorage) -> Result<Hash32, BlockAuthorError> {
        let new_header_hash = storage
            .header_db()
            .commit_header(self.new_block.header.clone())
            .await?;
        tracing::info!("New block created. Header hash: {new_header_hash}");
        Ok(new_header_hash)
    }

    /// Runs the final two STFs.
    /// 1. Accumulates epoch entropy (`η0` --> `η0′`)
    /// 2. Appends a new block history entry (`β†` --> `β′`)
    async fn run_final_state_transition(
        &self,
        storage: &NodeStorage,
        new_header_hash: Hash32,
        vrf_sig: &VrfSig,
        stf_output: BlockExecutionOutput,
    ) -> Result<(), BlockAuthorError> {
        BlockExecutor::accumulate_entropy(storage, vrf_sig).await?;
        BlockExecutor::append_block_history(
            storage,
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
