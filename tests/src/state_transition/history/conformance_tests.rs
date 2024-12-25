//! Block history state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        generate_typed_tests,
        history::asn_types::{Input, JamInput, Output, State},
        state_transition::state_transition_test::{run_test_case, StateTransitionTest},
    };
    use rjam_common::ByteArray;
    use rjam_db::BlockHeaderDB;
    use rjam_state::StateManager;
    use rjam_transition::{
        error::TransitionError,
        state::history::{transition_block_history_append, transition_block_history_parent_root},
    };
    use rjam_types::{
        state::history::ReportedWorkPackage,
        state_utils::{StateEntryType, StateKeyConstant},
    };

    struct HistoryTest;

    impl StateTransitionTest for HistoryTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/history/data";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type Output = Output;
        type ErrorCode = ();

        fn setup_state_manager(
            test_pre_state: &Self::State,
        ) -> Result<StateManager, TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let prior_block_history = test_pre_state.clone().into();

            // Initialize StateManager.
            let mut state_manager = StateManager::new_for_test();

            // Load pre-state into the state cache.
            state_manager.load_state_for_test(
                StateKeyConstant::BlockHistory,
                StateEntryType::BlockHistory(prior_block_history),
            );

            Ok(state_manager)
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            let header_hash = ByteArray::new(test_input.header_hash.0);
            let parent_state_root = ByteArray::new(test_input.parent_state_root.0);
            let accumulate_root = ByteArray::new(test_input.accumulate_root.0);
            let reported_packages: Vec<ReportedWorkPackage> = test_input
                .work_packages
                .iter()
                .map(|reported| ReportedWorkPackage {
                    work_package_hash: ByteArray::new(reported.hash.0),
                    segment_root: ByteArray::new(reported.exports_root.0),
                })
                .collect();

            Ok(JamInput {
                header_hash,
                parent_state_root,
                accumulate_root,
                reported_packages,
            })
        }

        fn run_state_transition(
            state_manager: &StateManager,
            _header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
        ) -> Result<(), TransitionError> {
            // First transition: Prior state root integration.
            transition_block_history_parent_root(&state_manager, jam_input.parent_state_root)?;

            // Second transition: Append new history entry.
            transition_block_history_append(
                &state_manager,
                jam_input.header_hash,
                jam_input.accumulate_root,
                &jam_input.reported_packages,
            )?;

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
            state_manager.get_block_history().unwrap().into()
        }
    }

    generate_typed_tests! {
        HistoryTest,

        // Success
        // Empty history queue.
        progress_blocks_history_1: "progress_blocks_history-1.json",

        // Success
        // Not empty nor full history queue.
        progress_blocks_history_2: "progress_blocks_history-2.json",

        // Success
        // Fill the history queue.
        progress_blocks_history_3: "progress_blocks_history-3.json",

        // Success
        // Shift the history queue.
        progress_blocks_history_4: "progress_blocks_history-4.json",
    }
}
