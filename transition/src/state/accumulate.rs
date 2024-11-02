use crate::error::TransitionError;
use rjam_common::EPOCH_LENGTH;
use rjam_pvm_invocation::accumulation::utils::{edit_queue, map_segment_roots};
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::{
    common::workloads::WorkReport,
    state::{accumulate::DeferredWorkReport, timeslot::Timeslot},
};

/// State transition function of `AccumulateQueue`.
pub fn transition_accumulate_queue(
    state_manager: &StateManager,
    accumulatable_reports: &[WorkReport],    // W^*
    accumulated_reports: usize,              // n
    deferred_reports: &[DeferredWorkReport], // W^Q
    prior_timeslot: &Timeslot,               // tau
    current_timeslot: &Timeslot,             // tau'
) -> Result<(), TransitionError> {
    // TODO: Check the formal definition of the state transition -
    // TODO: the function `E` takes the history  mapping type as the second argument.
    // Represents `P(W^*_{...n})`.
    let accumulated_history = map_segment_roots(&accumulatable_reports[..accumulated_reports]);

    // Represents the current slot phase `m`.
    let slot_phase = (current_timeslot.slot() as usize % EPOCH_LENGTH) as isize;

    state_manager.with_mut_accumulate_queue(StateWriteOp::Update, |queue| {
        // Update ready queue for the current timeslot (i = 0).
        let current_slot_entry = queue.get_circular_mut(slot_phase);
        let current_slot_entry_updated =
            edit_queue(deferred_reports.to_vec(), &accumulated_history);
        current_slot_entry.drain(..);
        current_slot_entry.extend(current_slot_entry_updated);

        // Update ready queue for the skipped timeslots (1 <= i < (tau' - tau)).
        let skipped_slots = (current_timeslot.slot() - prior_timeslot.slot()) as usize;
        for i in 1..skipped_slots {
            let skipped_slot_entry = queue.get_circular_mut(slot_phase - i as isize);
            skipped_slot_entry.drain(..);
        }

        // Update ready queue for the older timeslots, within an epoch range (i >= (tau' - tau)).
        for i in skipped_slots..EPOCH_LENGTH {
            let old_entry = queue.get_circular_mut(slot_phase - i as isize);
            let old_entry_updated = edit_queue(old_entry.clone(), &accumulated_history);
            old_entry.drain(..);
            old_entry.extend(old_entry_updated);
        }
    })?;

    Ok(())
}

/// State transition function of `AccumulateHistory`.
pub fn transition_accumulate_history(
    state_manager: &StateManager,
    accumulatable_reports: &[WorkReport], // W^*
    accumulated_reports: usize,           // n
) -> Result<(), TransitionError> {
    assert!(accumulated_reports <= accumulatable_reports.len());
    let last_history = map_segment_roots(&accumulatable_reports[..accumulated_reports]);
    state_manager.with_mut_accumulate_history(StateWriteOp::Update, |history| {
        // Add the latest history entry, shifting by one entry if the list is full.
        history.add(last_history);
    })?;

    Ok(())
}
