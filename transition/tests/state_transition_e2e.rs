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
use std::error::Error;

#[tokio::test]
async fn state_transition_e2e() -> Result<(), Box<dyn Error>> {
    // Parent block context
    let parent_block = BlockHeader::default();
    let parent_hash = parent_block.hash()?;

    // Initialize DB
    let (mut header_db, state_manager) = init_db_and_manager(Some(parent_hash));
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

    // Header fields
    let pre_timeslot = state_manager.get_timeslot().await?;
    let header_timeslot = header_db.set_timeslot()?;
    let header_parent_state_root = state_manager.merkle_root(); // Assuming commitment of the parent stat is done here.
    let author_index = 0;

    // Timeslot STF
    transition_timeslot(&state_manager, &header_timeslot).await?;

    // Epoch progress check
    let curr_timeslot = state_manager.get_timeslot().await?;
    let epoch_progressed = pre_timeslot.epoch() < curr_timeslot.epoch();

    // Disputes STF
    let pre_timeslot = state_manager.get_timeslot().await?;
    let offenders_marker = disputes_xt.collect_offender_keys();
    transition_reports_eliminate_invalid(&state_manager, &disputes_xt, &pre_timeslot).await?;
    transition_disputes(&state_manager, &disputes_xt, &pre_timeslot).await?;
    header_db.set_offenders_marker(&offenders_marker)?;

    // Assurances STF
    let _removed_reports =
        transition_reports_clear_availables(&state_manager, &assurances_xt, &parent_hash).await?;

    // Reports STF
    let (_reported, _reporters) =
        transition_reports_update_entries(&state_manager, &guarantees_xt, &curr_timeslot).await?;

    // Authorizer STF
    transition_auth_pool(&state_manager, &guarantees_xt, &header_timeslot).await?;

    // Safrole STF
    let input_entropy = Hash32::default();
    transition_entropy_accumulator(&state_manager, epoch_progressed, input_entropy).await?;
    transition_past_set(&state_manager, epoch_progressed).await?;
    transition_active_set(&state_manager, epoch_progressed).await?;
    transition_safrole(&state_manager, &pre_timeslot, epoch_progressed, &tickets_xt).await?;
    let markers = mark_safrole_header_markers(&state_manager, epoch_progressed).await?;
    if let Some(epoch_marker) = markers.epoch_marker.as_ref() {
        header_db.set_epoch_marker(epoch_marker)?;
    }
    if let Some(winning_tickets_marker) = markers.winning_tickets_marker.as_ref() {
        header_db.set_winning_tickets_marker(winning_tickets_marker)?;
    }

    // Block summary
    let header_hash = Hash32::default();
    let accumulate_root = Hash32::default();
    let reported_packages: Vec<ReportedWorkPackage> = vec![];

    // Block History STF
    transition_block_history_parent_root(&state_manager, header_parent_state_root).await?;
    transition_block_history_append(
        &state_manager,
        header_hash,
        accumulate_root,
        &reported_packages,
    )
    .await?;

    // ValidatorStats STF
    transition_validator_stats(&state_manager, epoch_progressed, author_index, &xt_cloned).await?;

    // TODO: Block sealing, PVM Invocation
    Ok(())
}
