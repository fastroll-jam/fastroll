//! End-to-end state transition tests

use rjam_common::Hash32;
use rjam_state::test_utils::{add_all_simple_state_entries, init_db_and_manager};
use rjam_transition::{
    procedures::chain_extension::mark_safrole_header_markers,
    state::{
        authorizer::transition_auth_pool,
        disputes::transition_disputes,
        entropy::transition_entropy_accumulator,
        history::{transition_block_history_append, transition_block_history_parent_root},
        reports::{
            transition_reports_clear_availables, transition_reports_eliminate_invalid,
            transition_reports_update_entries,
        },
        safrole::transition_safrole,
        statistics::transition_validator_stats,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
use rjam_types::{block::header::BlockHeader, extrinsics::Extrinsics, state::ReportedWorkPackage};
use std::{error::Error, future::Future, sync::Arc, time::Instant};
use tokio::{join, task::JoinHandle};
use tracing::{info, subscriber::set_global_default};
use tracing_subscriber::{fmt, prelude::*, Registry};

fn spawn_timed<F, T>(task_name: &'static str, fut: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        let start = Instant::now();
        let result = fut.await;
        info!(%task_name, "Transitioned in {:?} μs", start.elapsed().as_micros());
        result
    })
}

#[tokio::test]
async fn state_transition_e2e() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_timer(fmt::time::uptime());
    let sub = Registry::default().with(fmt_layer);
    set_global_default(sub)?;

    // Parent block context
    let parent_block = BlockHeader::default();
    let parent_hash = parent_block.hash()?;

    // Initialize DB
    let (mut header_db, state_manager) = init_db_and_manager(Some(parent_hash));
    let state_manager = Arc::new(state_manager);
    add_all_simple_state_entries(&state_manager).await?;
    state_manager.commit_dirty_cache().await?;

    // Collect Extrinsics
    let xt = Extrinsics::default();
    header_db.set_extrinsic_hash(&xt)?;

    let xt_cloned = xt.clone();
    let disputes_xt = xt.disputes;
    let assurances_xt = xt.assurances;
    let guarantees_xt = xt.guarantees;
    let tickets_xt = xt.tickets;

    // Prepare Header Fields
    let prev_timeslot = state_manager.get_timeslot().await?;
    let header_timeslot = header_db.set_timeslot()?;
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
        transition_entropy_accumulator(
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
        let _removed_reports = transition_reports_clear_availables(
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
    let (offenders_marker, _, _, _) = join!(disputes_jh, entropy_jh, past_set_jh, active_set_jh);

    // Safrole STF
    let state_manager_cloned = state_manager.clone();
    let safrole_jh = spawn_timed("safrole_stf", async move {
        transition_safrole(
            state_manager_cloned.clone(),
            &prev_timeslot,
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

    // ValidatorStats STF
    let state_manager_cloned = state_manager.clone();
    let stats_jh = spawn_timed("stats_stf", async move {
        transition_validator_stats(
            state_manager_cloned,
            epoch_progressed,
            author_index,
            &xt_cloned,
        )
        .await
        .unwrap();
    });

    // Join remaining STF tasks
    let (_, _, _, safrole_markers_result, _) =
        join!(reports_jh, auth_pool_jh, history_jh, safrole_jh, stats_jh);

    // Set header markers
    header_db.set_offenders_marker(&offenders_marker?)?;
    let safrole_markers = safrole_markers_result?;
    if let Some(epoch_marker) = safrole_markers.epoch_marker.as_ref() {
        header_db.set_epoch_marker(epoch_marker)?;
    }
    if let Some(winning_tickets_marker) = safrole_markers.winning_tickets_marker.as_ref() {
        header_db.set_winning_tickets_marker(winning_tickets_marker)?;
    }

    // TODO: Block sealing, PVM Invocation
    Ok(())
}
