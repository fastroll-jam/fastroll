use crate::error::TransitionError;
use fr_common::{workloads::work_report::WorkReport, EPOCH_LENGTH};
use fr_pvm_invocation::accumulate::utils::{edit_queue, reports_to_package_hashes};
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{Timeslot, WorkReportDepsMap},
};
use std::{collections::BTreeSet, sync::Arc};

/// State transition function of `AccumulateQueue`.
pub async fn transition_accumulate_queue(
    state_manager: Arc<StateManager>,
    queued_reports: &[WorkReportDepsMap], // R^Q
    prior_timeslot: Timeslot,             // τ
    curr_timeslot: Timeslot,              // τ'
) -> Result<(), TransitionError> {
    let accumulate_history = state_manager.get_accumulate_history().await?;
    let last_accumulate_set = accumulate_history
        .last_history()
        .expect("Should not be empty");

    let last_accumulate_set_vec = last_accumulate_set.iter().cloned().collect::<Vec<_>>();

    // Represents the current slot phase `m`.
    let slot_phase = (curr_timeslot.slot() as usize % EPOCH_LENGTH) as isize;

    state_manager
        .with_mut_accumulate_queue(StateMut::Update, |queue| -> Result<(), StateManagerError> {
            // Update accumulate queue for the current timeslot (i = 0).
            let curr_slot_entry = queue.get_circular_mut(slot_phase);
            let curr_slot_entry_updated = edit_queue(queued_reports, &last_accumulate_set_vec);
            curr_slot_entry.drain(..);
            curr_slot_entry.extend(curr_slot_entry_updated);

            // Update accumulate queue for the skipped timeslots (1 <= i < (τ' - τ)).
            let skipped_slots = (curr_timeslot.slot() - prior_timeslot.slot()) as usize;
            for i in 1..skipped_slots {
                let skipped_slot_entry = queue.get_circular_mut(slot_phase - i as isize);
                skipped_slot_entry.drain(..);
            }

            // Update ready accumulate for the older timeslots, within an epoch range (i >= (τ' - τ)).
            for i in skipped_slots..EPOCH_LENGTH {
                let old_entry = queue.get_circular_mut(slot_phase - i as isize);
                let old_entry_updated = edit_queue(old_entry.as_ref(), &last_accumulate_set_vec);
                old_entry.drain(..);
                old_entry.extend(old_entry_updated);
            }
            Ok(())
        })
        .await?;

    Ok(())
}

/// State transition function of `AccumulateHistory`.
pub async fn transition_accumulate_history(
    state_manager: Arc<StateManager>,
    accumulatable_reports: &[WorkReport], // R^*
    accumulate_count: usize,              // n
) -> Result<(), TransitionError> {
    assert!(accumulate_count <= accumulatable_reports.len());
    // Represents `P(R^*_{...n})`.
    let accumulated = reports_to_package_hashes(&accumulatable_reports[..accumulate_count]);

    state_manager
        .with_mut_accumulate_history(
            StateMut::Update,
            |history| -> Result<(), StateManagerError> {
                // Add the latest history entry, shifting by one entry if the list is full.
                history.add(BTreeSet::from_iter(accumulated.into_iter()));
                Ok(())
            },
        )
        .await?;

    Ok(())
}
