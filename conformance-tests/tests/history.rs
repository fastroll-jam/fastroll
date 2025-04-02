//! Block history state transition conformance tests
mod history {
    use async_trait::async_trait;
    use rjam_block::header_db::BlockHeaderDB;
    use rjam_common::{workloads::ReportedWorkPackage, Hash32};
    use rjam_conformance_tests::{
        asn_types::history::*,
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use rjam_state::{error::StateManagerError, manager::StateManager, types::BlockHistory};
    use rjam_transition::{
        error::TransitionError,
        state::history::{transition_block_history_append, transition_block_history_parent_root},
    };
    use std::sync::Arc;

    struct HistoryTest;

    #[async_trait]
    impl StateTransitionTest for HistoryTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/history/data";

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
            let pre_block_history = BlockHistory::from(test_pre_state.beta.clone());

            // Load pre-state into the state cache.
            state_manager.add_block_history(pre_block_history).await?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            let header_hash = Hash32::from(test_input.header_hash);
            let parent_state_root = Hash32::from(test_input.parent_state_root);
            let accumulate_root = Hash32::from(test_input.accumulate_root);
            let reported_packages: Vec<ReportedWorkPackage> = test_input
                .work_packages
                .iter()
                .map(|reported| ReportedWorkPackage {
                    work_package_hash: Hash32::from(reported.hash),
                    segment_root: Hash32::from(reported.exports_root),
                })
                .collect();

            Ok(JamInput {
                header_hash,
                parent_state_root,
                accumulate_root,
                reported_packages,
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            _header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // First transition: Prior state root integration.
            transition_block_history_parent_root(
                state_manager.clone(),
                jam_input.parent_state_root,
            )
            .await?;

            // Second transition: Append new history entry.
            transition_block_history_append(
                state_manager,
                jam_input.header_hash,
                jam_input.accumulate_root,
                &jam_input.reported_packages,
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
            Ok(State {
                beta: state_manager.get_block_history().await?.into(),
            })
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
