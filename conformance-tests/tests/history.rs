//! Block history state transition conformance tests
mod tests {
    use async_trait::async_trait;
    use rjam_conformance_tests::harness::run_test_case;
    use std::sync::Arc;

    use rjam_common::ByteArray;
    use rjam_conformance_tests::{
        asn_types::history::*, generate_typed_tests, harness::StateTransitionTest,
    };
    use rjam_db::header_db::BlockHeaderDB;
    use rjam_state::{error::StateManagerError, StateManager};
    use rjam_transition::{
        error::TransitionError,
        state::history::{transition_block_history_append, transition_block_history_parent_root},
    };
    use rjam_types::state::{history::ReportedWorkPackage, BlockHistory};

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

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            _header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
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
