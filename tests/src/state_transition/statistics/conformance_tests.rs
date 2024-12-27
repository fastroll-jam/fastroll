//! Statistics state transition conformance tests
#[cfg(test)]
mod test {
    use crate::{
        asn_types::{validator_set_to_validators_data, validators_data_to_validator_set},
        generate_typed_tests,
        state_transition::{
            state_transition_test::{run_test_case, StateTransitionTest},
            statistics::asn_types::{Input, JamInput, Output, State},
        },
    };
    use rjam_db::BlockHeaderDB;
    use rjam_state::StateManager;
    use rjam_transition::{error::TransitionError, state::statistics::transition_validator_stats};
    use rjam_types::{
        extrinsics::Extrinsics,
        state::{ActiveSet, Timeslot, ValidatorStats},
        state_utils::{StateEntryType, StateKeyConstant},
    };

    struct StatisticsTest;

    impl StateTransitionTest for StatisticsTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/statistics/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = ();
        type Output = Output;
        type ErrorCode = ();

        fn setup_state_manager(
            test_pre_state: &Self::State,
        ) -> Result<StateManager, TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let prior_validator_stats = ValidatorStats::from(test_pre_state.pi.clone());
            let prior_timeslot = Timeslot::new(test_pre_state.tau);
            let posterior_active_set = ActiveSet(validators_data_to_validator_set(
                &test_pre_state.kappa_prime,
            ));

            // Initialize StateManager.
            let mut state_manager = StateManager::new_for_test();

            // Load pre-state info the state cache.
            state_manager.load_state_for_test(
                StateKeyConstant::ValidatorStats,
                StateEntryType::ValidatorStats(prior_validator_stats),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::Timeslot,
                StateEntryType::Timeslot(prior_timeslot),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::ActiveSet,
                StateEntryType::ActiveSet(posterior_active_set),
            );

            Ok(state_manager)
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            Ok(JamInput {
                timeslot: Timeslot::new(test_input.slot),
                author_index: test_input.author_index,
                extrinsics: Extrinsics::from(test_input.extrinsic.clone()),
            })
        }

        fn run_state_transition(
            state_manager: &StateManager,
            _header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // Run state transitions.
            let prior_timeslot = state_manager.get_timeslot()?;
            let next_timeslot = jam_input.timeslot;
            let epoch_progressed = prior_timeslot.epoch() < next_timeslot.epoch();

            transition_validator_stats(
                state_manager,
                epoch_progressed,
                jam_input.author_index,
                &jam_input.extrinsics,
            )?;
            Ok(())
        }

        fn map_error_code(_e: TransitionError) -> Self::ErrorCode {
            // No custom error code
        }

        fn extract_output(
            _header_db: &BlockHeaderDB,
            _transition_output: Option<&Self::JamTransitionOutput>,
            _error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            Output
        }

        fn extract_post_state(
            state_manager: &StateManager,
            _pre_state: &Self::State,
            _error_code: &Option<Self::ErrorCode>,
        ) -> Self::State {
            // Get the posterior state from the state cache.
            let current_validator_stats = state_manager.get_validator_stats().unwrap();
            let current_timeslot = state_manager.get_timeslot().unwrap();
            let posterior_active_set = state_manager.get_active_set().unwrap();

            // Convert RJAM types post-state into ASN post-state
            State {
                pi: current_validator_stats.into(),
                tau: current_timeslot.slot(),
                kappa_prime: validator_set_to_validators_data(&posterior_active_set),
            }
        }
    }

    generate_typed_tests! {
        StatisticsTest,

        // Empty extrinsic with no epoch change.
        // Only author blocks counter is incremented.
        stats_with_empty_extrinsic_1: "stats_with_empty_extrinsic-1.json",

        // Misc extrinsic information with no epoch change.
        stats_with_epoch_change_1: "stats_with_epoch_change-1.json",

        // Misc extrinsic information with no epoch change.
        stats_with_some_extrinsic_1: "stats_with_some_extrinsic-1.json",
    }
}
