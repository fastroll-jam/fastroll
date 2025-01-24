//! End-to-end state transition tests

use rjam_common::{Hash32, ValidatorIndex};
use rjam_state::test_utils::{add_all_simple_state_entries, init_db_and_manager};
use rjam_transition::{
    header::{
        set_header_epoch_marker, set_header_offenders_marker, set_header_winning_tickets_marker,
    },
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
use rjam_types::{
    extrinsics::Extrinsics,
    state::{ReportedWorkPackage, Timeslot},
};
use std::error::Error;

#[test]
fn state_transition_e2e() -> Result<(), Box<dyn Error>> {
    // Initialize state
    let (mut header_db, state_manager) = init_db_and_manager();
    add_all_simple_state_entries(&state_manager)?;
    state_manager.commit_dirty_cache()?;

    // Collect Extrinsics
    let xt = Extrinsics::default();
    let xt_cloned = xt.clone();
    let disputes_xt = xt.disputes;
    let assurances_xt = xt.assurances;
    let guarantees_xt = xt.guarantees;
    let tickets_xt = xt.tickets;

    // Header fields
    let pre_timeslot = Timeslot::default();
    let header_timeslot = Timeslot::new(1);
    let header_parent_hash = Hash32::default();
    let header_parent_state_root = Hash32::default();
    let author_index: ValidatorIndex = 0;

    // Timeslot STF
    transition_timeslot(&state_manager, &header_timeslot)?;

    // Epoch progress check
    let curr_timeslot = state_manager.get_timeslot()?;
    let epoch_progressed = pre_timeslot.epoch() < curr_timeslot.epoch();

    // Disputes STF
    let pre_timeslot = state_manager.get_timeslot()?;
    let offenders_marker = disputes_xt.collect_offender_keys();
    transition_reports_eliminate_invalid(&state_manager, &disputes_xt, &pre_timeslot)?;
    transition_disputes(&state_manager, &disputes_xt, &pre_timeslot)?;
    set_header_offenders_marker(&mut header_db, &offenders_marker)?;

    // Assurances STF
    let _removed_reports =
        transition_reports_clear_availables(&state_manager, &assurances_xt, &header_parent_hash)?;

    // Reports STF
    let (_reported, _reporters) =
        transition_reports_update_entries(&state_manager, &guarantees_xt, &curr_timeslot)?;

    // Authorizer STF
    transition_auth_pool(&state_manager, &guarantees_xt, &header_timeslot)?;

    // Safrole STF
    let input_entropy = Hash32::default();
    transition_entropy_accumulator(&state_manager, epoch_progressed, input_entropy)?;
    transition_past_set(&state_manager, epoch_progressed)?;
    transition_active_set(&state_manager, epoch_progressed)?;
    transition_safrole(&state_manager, &pre_timeslot, epoch_progressed, &tickets_xt)?;
    let markers = mark_safrole_header_markers(&state_manager, epoch_progressed)?;
    if let Some(epoch_marker) = markers.epoch_marker.as_ref() {
        set_header_epoch_marker(&mut header_db, epoch_marker)?;
    }
    if let Some(winning_tickets_marker) = markers.winning_tickets_marker.as_ref() {
        set_header_winning_tickets_marker(&mut header_db, winning_tickets_marker)?;
    }

    // Block summary
    let header_hash = Hash32::default();
    let accumulate_root = Hash32::default();
    let reported_packages: Vec<ReportedWorkPackage> = vec![];

    // Block History STF
    transition_block_history_parent_root(&state_manager, header_parent_state_root)?;
    transition_block_history_append(
        &state_manager,
        header_hash,
        accumulate_root,
        &reported_packages,
    )?;

    // ValidatorStats STF
    transition_validator_stats(&state_manager, epoch_progressed, author_index, &xt_cloned)?;

    Ok(())
}
