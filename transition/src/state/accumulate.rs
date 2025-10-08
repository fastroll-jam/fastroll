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
    let skipped_slots_capped =
        ((curr_timeslot.slot() - prior_timeslot.slot()) as usize).min(EPOCH_LENGTH);
    let curr_slot_entry_updated = edit_queue(queued_reports, &last_accumulate_set_vec);

    state_manager
        .with_mut_accumulate_queue(StateMut::Update, |queue| -> Result<(), StateManagerError> {
            // Update accumulate queue for the skipped timeslots (1 <= i < (τ' - τ)).
            for i in 1..skipped_slots_capped {
                queue.get_circular_mut(slot_phase - i as isize).clear();
            }

            // Update accumulate queue for the older timeslots, within an epoch range (i >= (τ' - τ)).
            for i in skipped_slots_capped..EPOCH_LENGTH {
                let idx = slot_phase - i as isize;
                let old_entry_updated =
                    edit_queue(queue.get_circular(idx), &last_accumulate_set_vec);
                let old_entry_mut = queue.get_circular_mut(idx);
                old_entry_mut.clear();
                old_entry_mut.extend(old_entry_updated);
            }

            // Update accumulate queue for the current timeslot (i = 0).
            let curr_slot_entry_mut = queue.get_circular_mut(slot_phase);
            curr_slot_entry_mut.clear();
            curr_slot_entry_mut.extend(curr_slot_entry_updated);
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
