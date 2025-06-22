use crate::error::TransitionError;
use fr_block::types::extrinsics::disputes::DisputesXt;
use fr_crypto::types::Ed25519PubKey;
use fr_extrinsics::validation::disputes::DisputesXtValidator;
use fr_state::{cache::StateMut, error::StateManagerError, manager::StateManager, types::Timeslot};
use std::sync::Arc;

/// State transition function of `Disputes`.
///
/// # Transitions
///
/// Merges the `good set`, `bad set`, and `wonky set` into the `Disputes` state.
/// Additionally, it compiles entries from the `culprits` and `faults` from the disputes system and
/// adds them to the `punish set`, identifying them as offenders.
pub async fn transition_disputes(
    state_manager: Arc<StateManager>,
    disputes_xt: &DisputesXt,
    prior_timeslot: Timeslot,
) -> Result<(), TransitionError> {
    let disputes_validator = DisputesXtValidator::new(state_manager.clone());
    disputes_validator
        .validate(disputes_xt, &prior_timeslot)
        .await?;

    let (good_set, bad_set, wonky_set) = disputes_xt.split_report_set();
    let culprits_keys = disputes_xt.culprits_keys();
    let faults_keys = disputes_xt.faults_keys();
    let offenders_keys: Vec<Ed25519PubKey> = culprits_keys.into_iter().chain(faults_keys).collect();

    state_manager
        .with_mut_disputes(
            StateMut::Update,
            |disputes| -> Result<(), StateManagerError> {
                disputes.sort_extend_good_set(good_set);
                disputes.sort_extend_bad_set(bad_set);
                disputes.sort_extend_wonky_set(wonky_set);
                disputes.sort_extend_punish_set(offenders_keys);
                Ok(())
            },
        )
        .await?;

    Ok(())
}
