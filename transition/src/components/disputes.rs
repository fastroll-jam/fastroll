use crate::error::TransitionError;
use rjam_common::Hash32;
use rjam_state::{StateManager, StateWriteOp};
use std::collections::HashSet;

/// State transition function of `Disputes`.
///
/// # Transitions
///
/// Merges the `good set`, `bad set`, and `wonky set` into the `Disputes` state.
/// Additionally, it compiles entries from the `culprits` and `faults` from the disputes system and
/// adds them to the `punish set`, ensuring that the effective punishments can be taken against the
/// identified culprits and faults.
pub fn transition_disputes(
    state_manager: &StateManager,
    good_set: &HashSet<Hash32>,
    bad_set: &HashSet<Hash32>,
    wonky_set: &HashSet<Hash32>,
    culprits_set: &HashSet<Hash32>,
    faults_set: &HashSet<Hash32>,
) -> Result<(), TransitionError> {
    state_manager.with_mut_disputes(StateWriteOp::Update, |disputes| {
        disputes.good_set.extend(good_set.iter());
        disputes.bad_set.extend(bad_set.iter());
        disputes.wonky_set.extend(wonky_set.iter());
        disputes
            .punish_set
            .extend(culprits_set.iter().chain(faults_set.iter()));
    })?;

    Ok(())
}
