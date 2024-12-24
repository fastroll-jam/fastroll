//! Authorizers state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        authorizations::asn_types::{Input, Output, State, TestCase},
        generate_tests,
        test_utils::load_test_case,
    };
    use rjam_state::StateManager;
    use rjam_transition::{error::TransitionError, state::authorizer::transition_auth_pool};
    use rjam_types::{
        extrinsics::guarantees::GuaranteesExtrinsic,
        state::{AuthPool, AuthQueue, Timeslot},
        state_utils::{StateEntryType, StateKeyConstant},
    };
    use std::path::PathBuf;

    const PATH_PREFIX: &str = "jamtestvectors-polkajam/authorizations/tiny";

    // Returns the actual post state, to be compared with the test post state.
    fn run_state_transition(
        test_input: &Input,
        test_pre_state: &State,
    ) -> Result<(State, Output), TransitionError> {
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

        // Convert ASN Input into RJAM types.
        let input_timeslot = Timeslot::new(test_input.slot);
        let input_extrinsic: GuaranteesExtrinsic = test_input.clone().into();

        // Run state transitions.
        transition_auth_pool(&state_manager, &input_extrinsic, &input_timeslot)?;

        // Get the posterior state from the state cache.
        let current_auth_pool = state_manager.get_auth_pool()?;
        let current_auth_queue = state_manager.get_auth_queue()?;

        let post_state = State {
            auth_pools: current_auth_pool.into(),
            auth_queues: current_auth_queue.into(),
        };

        Ok((post_state, Output))
    }

    fn run_test_case(filename: &str) -> Result<(), TransitionError> {
        let path = PathBuf::from(PATH_PREFIX).join(filename);
        let test_case: TestCase = load_test_case(&path).expect("Failed to load test vector.");
        let expected_post_state = test_case.post_state;

        let (post_state, _output) = run_state_transition(&test_case.input, &test_case.pre_state)?;

        // Assertion on the post state
        assert_eq!(post_state.auth_pools, expected_post_state.auth_pools);
        assert_eq!(post_state.auth_queues, expected_post_state.auth_queues);

        Ok(())
    }

    generate_tests! {
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
