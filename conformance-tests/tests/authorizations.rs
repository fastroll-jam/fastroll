//! Authorizers state transition conformance tests
mod tests {
    use async_trait::async_trait;
    use rjam_conformance_tests::harness::run_test_case;
    use std::sync::Arc;

    use rjam_conformance_tests::{
        asn_types::authorizations::*, generate_typed_tests, harness::StateTransitionTest,
    };
    use rjam_db::header_db::BlockHeaderDB;
    use rjam_state::{error::StateManagerError, StateManager};
    use rjam_transition::{error::TransitionError, state::authorizer::transition_auth_pool};
    use rjam_types::{
        extrinsics::guarantees::GuaranteesXt,
        state::{AuthPool, AuthQueue, Timeslot},
    };

    struct AuthorizationsTest;

    #[async_trait]
    impl StateTransitionTest for AuthorizationsTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/authorizations/tiny";

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
            let pre_auth_pool = AuthPool::from(test_pre_state.auth_pools.clone());
            let pre_auth_queue = AuthQueue::from(test_pre_state.auth_queues.clone());

            // Load pre-state info the state cache.
            state_manager.add_auth_pool(pre_auth_pool).await?;
            state_manager.add_auth_queue(pre_auth_queue).await?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            let input_timeslot = Timeslot::new(test_input.slot);
            let input_extrinsic: GuaranteesXt = test_input.clone().into();

            Ok(JamInput {
                slot: input_timeslot,
                extrinsic: input_extrinsic,
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            _header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // Run state transitions.
            transition_auth_pool(state_manager, &jam_input.extrinsic, jam_input.slot).await?;
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
            let curr_auth_pool = state_manager.get_auth_pool().await?;
            let curr_auth_queue = state_manager.get_auth_queue().await?;

            Ok(State {
                auth_pools: curr_auth_pool.into(),
                auth_queues: curr_auth_queue.into(),
            })
        }
    }

    generate_typed_tests! {
        AuthorizationsTest,

        // No guarantees.
        // Shift auths left from both pools.
        progress_authorizations_1: "progress_authorizations-1.json",

        // Guarantees for cores 0 and 1.
        // Consume authentication from both cores pools.
        progress_authorizations_2: "progress_authorizations-2.json",

        // Guarantees for core 1.
        // Shift left authentications for core 0 pool.
        // Consume authentication for core 1 pool.
        progress_authorizations_3: "progress_authorizations-3.json",
    }
}
