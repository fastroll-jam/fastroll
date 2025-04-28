//! End-to-end state transition tests
use rjam_block::{
    header_db::BlockHeaderDB,
    types::{
        block::{Block, BlockHeader},
        extrinsics::Extrinsics,
    },
};
use rjam_common::{utils::tracing::setup_timed_tracing, ByteArray, Hash32, ValidatorIndex};
use rjam_crypto::types::BandersnatchSecretKey;
use rjam_node::roles::{
    author::{sign_block_seal, sign_entropy_source_vrf_signature, sign_fallback_block_seal},
    executor::BlockExecutor,
};
use rjam_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
    types::SlotSealer,
};
use std::{error::Error, sync::Arc};

/// Mocking BlockHeader DB
fn get_parent_header() -> BlockHeader {
    BlockHeader::default()
}

/// Mocking Extrinsics Pool
fn get_all_extrinsics() -> Extrinsics {
    Extrinsics::default()
}

/// Mocking Author Info
fn get_author_index() -> ValidatorIndex {
    ValidatorIndex::default()
}

/// Mocking DB initialization and previous state.
///
/// This sets `parent_hash` and `parent_state_root` fields of `BlockHeader` during the initialization.
async fn init_with_prev_state(
    parent_hash: Hash32,
) -> Result<(BlockHeaderDB, Arc<StateManager>), Box<dyn Error>> {
    let (mut header_db, state_manager) = init_db_and_manager(Some(parent_hash));
    let state_manager = Arc::new(state_manager);
    add_all_simple_state_entries(&state_manager).await?;
    state_manager.commit_dirty_cache().await?;
    let prev_state_root = state_manager.merkle_root();
    header_db.set_parent_state_root(prev_state_root.clone())?;
    tracing::info!("Prev State Root: {}", prev_state_root);
    Ok((header_db, state_manager))
}

/// Mocking block author actor
#[tokio::test]
async fn state_transition_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_timed_tracing();

    let secret_key = BandersnatchSecretKey(ByteArray::default()); // FIXME: properly handle secret keys

    let xt = get_all_extrinsics(); // TODO: validate Xts

    // Set header fields required for running STFs in advance
    let parent_hash = get_parent_header().hash()?;
    tracing::info!("Parent header hash: {}", parent_hash);
    let (mut header_db, state_manager) = init_with_prev_state(parent_hash.clone()).await?;
    let parent_state_root = state_manager.merkle_root(); // Assuming commitment of the parent stat is done here.
    tracing::info!("Parent state root: {}", parent_state_root);
    let author_index = get_author_index();

    header_db.set_parent_state_root(parent_state_root.clone())?;
    header_db.set_block_author_index(author_index)?;
    header_db.set_timeslot()?;
    header_db.set_extrinsic_hash(&xt)?;

    // Construct a block with some header fields missing
    let staging_header = header_db
        .get_staging_header()
        .expect("Staging header should be initialized");
    let mut block = Block {
        header: staging_header,
        extrinsics: xt,
    };

    // Run state transitions
    let block_executor = BlockExecutor::new(state_manager.clone());
    let output = block_executor.run_state_transition(&block).await?;

    // Set header VRF signature
    let curr_timeslot = state_manager.get_timeslot().await?;
    let curr_slot_sealer = state_manager
        .get_safrole()
        .await?
        .slot_sealers
        .get_slot_sealer(&curr_timeslot);
    let epoch_entropy = state_manager.get_epoch_entropy().await?;
    let curr_entropy_3 = epoch_entropy.third_history();

    let vrf_sig =
        sign_entropy_source_vrf_signature(&curr_slot_sealer, curr_entropy_3, &secret_key)?;
    header_db.set_vrf_signature(&vrf_sig)?;

    // Set header markers
    header_db.set_offenders_marker(&output.offenders_marker)?;
    if let Some(epoch_marker) = output.safrole_markers.epoch_marker.as_ref() {
        header_db.set_epoch_marker(epoch_marker)?;
    }
    if let Some(winning_tickets_marker) = output.safrole_markers.winning_tickets_marker.as_ref() {
        header_db.set_winning_tickets_marker(winning_tickets_marker)?;
    }

    let header_data = header_db
        .get_staging_header()
        .expect("should exist")
        .header_data;

    // Seal the block
    let seal = match curr_slot_sealer {
        SlotSealer::Ticket(ticket) => {
            sign_block_seal(header_data, &ticket, curr_entropy_3, &secret_key)?
        }
        SlotSealer::BandersnatchPubKeys(_key) => {
            sign_fallback_block_seal(header_data, curr_entropy_3, &secret_key)?
        }
    };
    header_db.set_block_seal(&seal)?;

    // Commit the staging header
    let new_header_hash = header_db.commit_staging_header().await?;
    let new_header = header_db
        .get_header(&new_header_hash)
        .await?
        .expect("should exist");

    // Update the block header with the final header state
    block.header = new_header;
    tracing::info!("New block created. Header hash: {new_header_hash}");

    // The final two STFs: accumulate epoch entropy & append new block history entry
    block_executor.accumulate_entropy(&vrf_sig).await?;
    block_executor
        .append_block_history(
            new_header_hash,
            output.accumulate_root,
            output.reported_packages,
        )
        .await?;

    // TODO: Defer more STF runs to post-header-commit.

    // Commit the state transitions
    // Note: Also some STFs can be run asynchronously after committing the header.
    state_manager.commit_dirty_cache().await?;
    tracing::info!("Post State Root: {}", state_manager.merkle_root());

    Ok(())
}
