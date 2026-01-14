use crate::{error::TransitionError, ring_cache::compute_effective_staging_set_hash};
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
    offenders: Vec<Ed25519PubKey>,
    prior_timeslot: Timeslot,
) -> Result<(), TransitionError> {
    let disputes_validator = DisputesXtValidator::new(state_manager.clone());
    disputes_validator
        .validate(disputes_xt, &prior_timeslot)
        .await?;

    let (good_set, bad_set, wonky_set) = disputes_xt.split_report_set();

    state_manager
        .with_mut_disputes(
            StateMut::Update,
            |disputes| -> Result<(), StateManagerError> {
                disputes.sort_extend_good_set(good_set);
                disputes.sort_extend_bad_set(bad_set);
                disputes.sort_extend_wonky_set(wonky_set);
                disputes.sort_extend_punish_set(offenders);
                Ok(())
            },
        )
        .await?;

    match state_manager.get_staging_set().await {
        Ok(staging_set) => {
            let punish_set = state_manager.get_disputes().await?.punish_set;
            let effective_staging_set_hash =
                compute_effective_staging_set_hash(&staging_set, &punish_set)?;
            state_manager.update_last_staging_set_hash(effective_staging_set_hash);
        }
        Err(StateManagerError::StateKeyNotInitialized(_)) => {
            // Disputes STF tests do not always load the staging set.
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
