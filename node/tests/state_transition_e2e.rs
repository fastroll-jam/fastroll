//! End-to-end state transition tests
use rjam_block::{
    header_db::BlockHeaderDB,
    types::{block::BlockHeader, extrinsics::Extrinsics},
};
use rjam_common::{
    utils::tracing::setup_timed_tracing, workloads::work_report::ReportedWorkPackage, ByteArray,
    Hash32, ValidatorIndex,
};
use rjam_crypto::types::BandersnatchSecretKey;
use rjam_node::{
    roles::author::{sign_block_seal, sign_entropy_source_vrf_signature, sign_fallback_block_seal},
    utils::spawn_timed,
};
use rjam_pvm_invocation::pipeline::{
    accumulate_result_commitment, utils::collect_accumulatable_reports,
};
use rjam_state::{
    manager::StateManager,
    test_utils::{add_all_simple_state_entries, init_db_and_manager},
    types::{SlotSealer, Timeslot},
};
use rjam_transition::{
    procedures::chain_extension::mark_safrole_header_markers,
    state::{
        accumulate::{transition_accumulate_history, transition_accumulate_queue},
        authorizer::transition_auth_pool,
        disputes::transition_disputes,
        entropy::transition_epoch_entropy,
        history::{transition_block_history_append, transition_block_history_parent_root},
        reports::{
            transition_reports_clear_availables, transition_reports_eliminate_invalid,
            transition_reports_update_entries,
        },
        safrole::transition_safrole,
        services::transition_on_accumulate,
        statistics::transition_onchain_statistics,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
use std::{error::Error, sync::Arc};
use tokio::try_join;

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

    // Parent block context
    let parent_hash = get_parent_header().hash()?;
    tracing::info!("Parent header hash: {}", parent_hash);

    // Initialize prev state
    let (mut header_db, state_manager) = init_with_prev_state(parent_hash.clone()).await?;

    // Set block author index
    header_db.set_block_author_index(get_author_index())?;

    // Collect Extrinsics
    let xt = get_all_extrinsics();
    header_db.set_extrinsic_hash(&xt)?;

    let xt_cloned = xt.clone();
    let disputes_xt = xt.disputes;
    let assurances_xt = xt.assurances;
    let guarantees_xt = xt.guarantees;
    let tickets_xt = xt.tickets;

    // Prepare Header Fields
    let prev_timeslot = state_manager.get_timeslot().await?;
    let header_timeslot = Timeslot::new(header_db.set_timeslot()?);
    let header_parent_state_root = state_manager.merkle_root(); // Assuming commitment of the parent stat is done here.
    let author_index = 0;

    // Timeslot STF
    let state_manager_cloned = state_manager.clone();
    spawn_timed("timeslot_stf", async move {
        transition_timeslot(state_manager_cloned, &header_timeslot).await
    })
    .await??;

    // Epoch progress check
    let curr_timeslot = state_manager.get_timeslot().await?;
    let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

    // Disputes STF
    let state_manager_cloned = state_manager.clone();
    let disputes_xt_cloned = disputes_xt.clone();

    let disputes_jh = spawn_timed("disputes_stf", async move {
        let offenders_marker = disputes_xt_cloned.collect_offender_keys();
        transition_disputes(state_manager_cloned, &disputes_xt_cloned, prev_timeslot)
            .await
            .unwrap();

        offenders_marker
    });

    // Entropy STF
    let input_entropy = Hash32::default();
    let state_manager_cloned = state_manager.clone();
    let entropy_jh = spawn_timed("entropy_stf", async move {
        transition_epoch_entropy(
            state_manager_cloned.clone(),
            epoch_progressed,
            input_entropy,
        )
        .await
        .unwrap();
    });

    // PastSet STF
    let state_manager_cloned = state_manager.clone();
    let past_set_jh = spawn_timed("past_set_stf", async move {
        transition_past_set(state_manager_cloned, epoch_progressed)
            .await
            .unwrap();
    });

    // ActiveSet STF
    let state_manager_cloned = state_manager.clone();
    let active_set_jh = spawn_timed("active_set_stf", async move {
        transition_active_set(state_manager_cloned, epoch_progressed)
            .await
            .unwrap();
    });

    // Reports STF
    let state_manager_cloned = state_manager.clone();
    let guarantees_xt_cloned = guarantees_xt.clone();
    let reports_jh = spawn_timed("reports_stf", async move {
        transition_reports_eliminate_invalid(
            state_manager_cloned.clone(),
            &disputes_xt,
            prev_timeslot,
        )
        .await
        .unwrap();
        let available_reports = transition_reports_clear_availables(
            state_manager_cloned.clone(),
            &assurances_xt,
            parent_hash,
        )
        .await
        .unwrap();
        let (_reported, _reporters) = transition_reports_update_entries(
            state_manager_cloned,
            &guarantees_xt_cloned,
            curr_timeslot,
        )
        .await
        .unwrap();
        available_reports
    });

    // Authorizer STF
    let state_manager_cloned = state_manager.clone();
    let auth_pool_jh = spawn_timed("auth_pool_stf", async move {
        transition_auth_pool(state_manager_cloned, &guarantees_xt, header_timeslot)
            .await
            .unwrap();
    });

    // Block summary
    let header_hash = Hash32::default();
    let accumulate_root = Hash32::default();
    let reported_packages: Vec<ReportedWorkPackage> = vec![];

    // Block History STF
    let state_manager_cloned = state_manager.clone();
    let history_jh = spawn_timed("history_stf", async move {
        transition_block_history_parent_root(
            state_manager_cloned.clone(),
            header_parent_state_root,
        )
        .await
        .unwrap();
        transition_block_history_append(
            state_manager_cloned,
            header_hash,
            accumulate_root,
            &reported_packages,
        )
        .await
        .unwrap();
    });

    // Join: Disputes, Entropy, PastSet, ActiveSet STF (dependencies for Safrole STF)
    let (offenders_marker, _, _, _) =
        try_join!(disputes_jh, entropy_jh, past_set_jh, active_set_jh)?;

    // Safrole STF
    let state_manager_cloned = state_manager.clone();
    let safrole_jh = spawn_timed("safrole_stf", async move {
        transition_safrole(
            state_manager_cloned.clone(),
            &prev_timeslot,
            &curr_timeslot,
            epoch_progressed,
            &tickets_xt,
        )
        .await
        .unwrap();
        // Return markers
        mark_safrole_header_markers(state_manager_cloned, epoch_progressed)
            .await
            .unwrap()
    });

    // OnChainStatistics STF
    let state_manager_cloned = state_manager.clone();
    let stats_jh = spawn_timed("stats_stf", async move {
        transition_onchain_statistics(
            state_manager_cloned,
            epoch_progressed,
            author_index,
            &xt_cloned,
        )
        .await
        .unwrap();
    });

    let available_reports = reports_jh.await?;

    // Accumulate STF
    let (accumulatable_reports, queued_reports) = collect_accumulatable_reports(
        available_reports,
        &state_manager.get_accumulate_queue().await?,
        &state_manager.get_accumulate_history().await?,
        prev_timeslot.slot(),
    );
    let state_manager_cloned = state_manager.clone();
    let acc_jh = spawn_timed("acc_stf", async move {
        let acc_summary =
            transition_on_accumulate(state_manager_cloned.clone(), &accumulatable_reports)
                .await
                .unwrap();
        transition_accumulate_history(
            state_manager_cloned.clone(),
            &accumulatable_reports,
            acc_summary.accumulated_reports_count,
        )
        .await
        .unwrap();
        transition_accumulate_queue(
            state_manager_cloned,
            &queued_reports,
            prev_timeslot,
            curr_timeslot,
        )
        .await
        .unwrap();
        accumulate_result_commitment(acc_summary.output_pairs)
    });

    // Join remaining STF tasks
    let (_acc_root, _, _, safrole_markers, _) =
        try_join!(acc_jh, auth_pool_jh, history_jh, safrole_jh, stats_jh)?;

    // Load state data to be used later
    let curr_slot_sealer = state_manager
        .get_safrole()
        .await?
        .slot_sealers
        .get_slot_sealer(&curr_timeslot);
    let epoch_entropy = state_manager.get_epoch_entropy().await?;
    let curr_entropy_3 = epoch_entropy.third_history();

    // Set header markers
    header_db.set_offenders_marker(&offenders_marker)?;
    if let Some(epoch_marker) = safrole_markers.epoch_marker.as_ref() {
        header_db.set_epoch_marker(epoch_marker)?;
    }
    if let Some(winning_tickets_marker) = safrole_markers.winning_tickets_marker.as_ref() {
        header_db.set_winning_tickets_marker(winning_tickets_marker)?;
    }

    let header_data = header_db
        .get_staging_header()
        .expect("should exist")
        .header_data;

    let secret_key = BandersnatchSecretKey(ByteArray::default()); // FIXME: properly handle secret keys

    // Set the VRF signature for the entropy source
    let vrf_sig =
        sign_entropy_source_vrf_signature(&curr_slot_sealer, curr_entropy_3, &secret_key)?;
    header_db.set_vrf_signature(&vrf_sig)?;

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
    tracing::info!("New block created. Header hash: {new_header_hash}");

    // Commit the state transitions
    // Note: Also some STFs can be run asynchronously after committing the header.
    state_manager.commit_dirty_cache().await?;
    tracing::info!("Post State Root: {}", state_manager.merkle_root());

    Ok(())
}
