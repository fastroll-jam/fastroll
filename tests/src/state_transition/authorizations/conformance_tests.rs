//! Authorizers state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        authorizations::asn_types::{Input, Output, State},
        generate_typed_tests,
    };
    use rjam_db::BlockHeaderDB;

    use crate::{
        authorizations::asn_types::JamInput,
        state_transition::state_transition_test::{run_test_case, StateTransitionTest},
    };
    use rjam_state::StateManager;
    use rjam_transition::{error::TransitionError, state::authorizer::transition_auth_pool};
    use rjam_types::{
        extrinsics::guarantees::GuaranteesExtrinsic,
        state::{AuthPool, AuthQueue, Timeslot},
        state_utils::{StateEntryType, StateKeyConstant},
    };

    struct AuthorizationsTest;

    impl StateTransitionTest for AuthorizationsTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/authorizations/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type Output = Output;
        type ErrorCode = ();

        fn setup_state_manager(
            test_pre_state: &Self::State,
        ) -> Result<StateManager, TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let prior_auth_pool = AuthPool::from(test_pre_state.auth_pools.clone());
            let prior_auth_queue = AuthQueue::from(test_pre_state.auth_queues.clone());

            // Initialize StateManager.
            let mut state_manager = StateManager::new_for_test();

            // Load pre-state info the state cache.
            state_manager.load_state_for_test(
                StateKeyConstant::AuthPool,
                StateEntryType::AuthPool(prior_auth_pool),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::AuthQueue,
                StateEntryType::AuthQueue(prior_auth_queue),
            );

            Ok(state_manager)
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            let input_timeslot = Timeslot::new(test_input.slot);
            let input_extrinsic: GuaranteesExtrinsic = test_input.clone().into();

            Ok(JamInput {
                slot: input_timeslot,
                extrinsic: input_extrinsic,
            })
        }

        fn run_state_transition(
            state_manager: &StateManager,
            _header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
        ) -> Result<(), TransitionError> {
            // Run state transitions.
            transition_auth_pool(&state_manager, &jam_input.extrinsic, &jam_input.slot)?;
            Ok(())
        }

        fn map_error_code(_e: TransitionError) -> Self::ErrorCode {
            // No custom error code
        }

        fn extract_output(
            _header_db: &BlockHeaderDB,
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
            let current_auth_pool = state_manager.get_auth_pool().unwrap();
            let current_auth_queue = state_manager.get_auth_queue().unwrap();

            State {
                auth_pools: current_auth_pool.into(),
                auth_queues: current_auth_queue.into(),
            }
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
