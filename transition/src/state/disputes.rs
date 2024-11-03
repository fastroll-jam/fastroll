use crate::error::TransitionError;
use rjam_extrinsics::validation::disputes::DisputesExtrinsicValidator;
use rjam_state::{StateManager, StateWriteOp};
use rjam_types::{extrinsics::disputes::DisputesExtrinsic, state::timeslot::Timeslot};

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
    disputes: &DisputesExtrinsic,
    prior_timeslot: &Timeslot,
) -> Result<(), TransitionError> {
    let disputes_validator = DisputesExtrinsicValidator::new(state_manager);
    disputes_validator.validate(disputes, prior_timeslot)?;

    let (good_set, bad_set, wonky_set) = disputes.split_report_set();
    let culprits_set = disputes.culprits_set();
    let faults_set = disputes.faults_set();

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
