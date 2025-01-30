//! Statistics state transition conformance tests
mod test {
    use async_trait::async_trait;
    use rjam_conformance_tests::{
        asn_types::{common::*, statistics::*},
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use std::sync::Arc;

    use rjam_db::header_db::BlockHeaderDB;
    use rjam_state::{error::StateManagerError, StateManager};
    use rjam_transition::{error::TransitionError, state::statistics::transition_validator_stats};
    use rjam_types::{
        extrinsics::Extrinsics,
        state::{ActiveSet, Timeslot, ValidatorStats},
    };

    struct StatisticsTest;

    #[async_trait]
    impl StateTransitionTest for StatisticsTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/statistics/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = ();
        type Output = Output;
        type ErrorCode = ();

        async fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: Arc<StateManager>,
        ) -> Result<(), StateManagerError> {
            // Convert ASN pre-state into RJAM types.
            let pre_validator_stats = ValidatorStats::from(test_pre_state.pi.clone());
            let pre_timeslot = Timeslot::new(test_pre_state.tau);
            let posterior_active_set = ActiveSet(validators_data_to_validator_set(
                &test_pre_state.kappa_prime,
            ));

            // Load pre-state info the state cache.
            state_manager
                .add_validator_stats(pre_validator_stats)
                .await?;
            state_manager.add_timeslot(pre_timeslot).await?;
            state_manager.add_active_set(posterior_active_set).await?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            Ok(JamInput {
                timeslot: Timeslot::new(test_input.slot),
                author_index: test_input.author_index,
                extrinsics: Extrinsics::from(test_input.extrinsic.clone()),
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            _header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // Run state transitions.
            let pre_timeslot = state_manager.get_timeslot().await?;
            let next_timeslot = jam_input.timeslot;
            let epoch_progressed = pre_timeslot.epoch() < next_timeslot.epoch();

            transition_validator_stats(
                state_manager,
                epoch_progressed,
                jam_input.author_index,
                jam_input.extrinsics,
            )
            .await?;
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

        async fn extract_post_state(
            state_manager: Arc<StateManager>,
            _pre_state: &Self::State,
            _error_code: &Option<Self::ErrorCode>,
        ) -> Result<Self::State, StateManagerError> {
            // Get the posterior state from the state cache.
            let curr_validator_stats = state_manager.get_validator_stats().await?;
            let curr_timeslot = state_manager.get_timeslot().await?;
            let posterior_active_set = state_manager.get_active_set().await?;

            // Convert RJAM types post-state into ASN post-state
            Ok(State {
                pi: curr_validator_stats.into(),
                tau: curr_timeslot.slot(),
                kappa_prime: validator_set_to_validators_data(&posterior_active_set),
            })
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
