#[cfg(test)]
mod tests {
    use crate::history::asn_types::{Input, Output, State, TestCase};
    use rjam_common::Hash32;
    use rjam_state::{StateEntryType, StateKeyConstant, StateManager};
    use rjam_transition::components::history::{
        transition_block_history_append, transition_block_history_parent_root,
    };
    use std::{error::Error, fs};

    // Load a test case from the test vector path
    fn load_test_case(path: &str) -> Result<TestCase, ()> {
        let full_path = format!(
            "{}/jamtestvectors-history/{}",
            env!("CARGO_MANIFEST_DIR"),
            path
        );
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_case)
    }

    // Returns the actual post state, to be compared with the test post state.
    fn run_state_transition(
        test_input: &Input,
        test_pre_state: &State,
    ) -> Result<(State, Output), Box<dyn Error>> {
        // Convert ASN pre-state into RJAM types.
        let prior_block_history = test_pre_state.clone().into();

        // Initialize StateManager.
        let mut state_manager = StateManager::new_for_test();

        // Load pre-state into the StateCache.
        state_manager.load_state_for_test(
            StateKeyConstant::BlockHistory,
            StateEntryType::BlockHistory(prior_block_history),
        );

        // Run BlockHistory state transitions.

        // First transition: Prior state root integration.
        transition_block_history_parent_root(&state_manager, test_input.parent_state_root.0)?;

        // Second transition: Append new history entry.
        let work_package_hashes: Vec<Hash32> =
            test_input.work_packages.iter().map(|hash| hash.0).collect();
        transition_block_history_append(
            &state_manager,
            test_input.header_hash.0,
            test_input.accumulate_root.0,
            &work_package_hashes,
        )?;

        // Get the posterior state from the StateCache.
        let current_block_history = state_manager.get_block_history()?;

        // Convert RJAM types post-state into ASN post-state
        let post_state = current_block_history.into();
        Ok((post_state, Output))
    }

    fn run_test_case(path: &str) -> Result<(), Box<dyn Error>> {
        let test_case = load_test_case(path).expect("Failed to load test vector.");
        let expected_post_state = test_case.post_state; // The expected post state.

        let (post_state, _output) = run_state_transition(&test_case.input, &test_case.pre_state)?;

        // Assertion on the post state
        assert_eq!(post_state.beta, expected_post_state.beta);

        Ok(())
    }

    macro_rules! generate_tests {
        ($($name:ident: $path:expr,)*) => {
            $(
                #[test]
                fn $name() -> Result<(), Box<dyn Error>> {
                    run_test_case($path)
                }
            )*
        }
    }

    generate_tests! {
        // Success
        // Empty history queue.
        progress_blocks_history_1: "history/data/progress_blocks_history-1.json",

        // Success
        // Not empty nor full history queue.
        progress_blocks_history_2: "history/data/progress_blocks_history-2.json",

        // Success
        // Fill the history queue.
        progress_blocks_history_3: "history/data/progress_blocks_history-3.json",

        // Success
        // Shift the history queue.
        progress_blocks_history_4: "history/data/progress_blocks_history-4.json",
    }
}
