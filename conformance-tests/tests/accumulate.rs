//! Accumulate state transition conformance tests
mod tests {
    use async_trait::async_trait;
    use futures::future::join_all;
    use rjam_common::ByteArray;
    use rjam_conformance_tests::{
        asn_types::accumulate::*,
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use rjam_db::header_db::BlockHeaderDB;
    use rjam_state::{error::StateManagerError, StateManager};
    use rjam_transition::{
        error::TransitionError,
        state::{services::transition_on_accumulate, timeslot::transition_timeslot},
    };
    use rjam_types::state::Timeslot;
    use std::sync::Arc;

    struct AccumulateTest;

    #[async_trait]
    impl StateTransitionTest for AccumulateTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/accumulate/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = JamTransitionOutput;
        type Output = Output;
        type ErrorCode = ();

        async fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: Arc<StateManager>,
        ) -> Result<(), StateManagerError> {
            todo!()
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            todo!()
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            todo!()
        }

        fn map_error_code(e: TransitionError) -> Self::ErrorCode {
            todo!()
        }

        fn extract_output(
            header_db: &BlockHeaderDB,
            transition_output: Option<&Self::JamTransitionOutput>,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            todo!()
        }

        async fn extract_post_state(
            state_manager: Arc<StateManager>,
            pre_state: &Self::State,
            error_code: &Option<Self::ErrorCode>,
        ) -> Result<Self::State, StateManagerError> {
            todo!()
        }
    }

    generate_typed_tests! {
        AccumulateTest,

        // No reports.
        no_available_reports_1: "no_available_reports-1.json",

        // Report with no dependencies.
        process_one_immediate_report_1: "process_one_immediate_report-1.json",

        // Report with unsatisfied dependency added to the ready-queue.
        enqueue_and_unlock_simple_1: "enqueue_and_unlock-simple-1.json",

        // Report with no dependencies that resolves previous dependency.
        enqueue_and_unlock_simple_2: "enqueue_and_unlock-simple-2.json",

        // Report with unsatisfied segment tree root dependency added to the ready-queue.
        enqueue_and_unlock_with_sr_lookup_1: "enqueue_and_unlock_with_sr_lookup-1.json",

        // Report with no dependencies that resolves previous dependency.
        enqueue_and_unlock_with_sr_lookup_2: "enqueue_and_unlock_with_sr_lookup-2.json",

        // Two reports with unsatisfied dependencies added to the ready-queue.
        enqueue_and_unlock_chain_1: "enqueue_and_unlock_chain-1.json",

        // Two additional reports with unsatisfied dependencies added to the ready-queue.
        enqueue_and_unlock_chain_2: "enqueue_and_unlock_chain-2.json",

        // Two additional reports. One with unsatisfied dependencies, thus added to the ready-queue.
        // One report is accumulated and resolves two previously enqueued reports.
        enqueue_and_unlock_chain_3: "enqueue_and_unlock_chain-3.json",

        // Report that resolves all remaining queued dependencies.
        enqueue_and_unlock_chain_4: "enqueue_and_unlock_chain-4.json",

        // Two reports with unsatisfied dependencies added to the ready-queue.
        enqueue_and_unlock_chain_wraps_1: "enqueue_and_unlock_chain_wraps-1.json",

        // Two additional reports, one with no dependencies and thus immediately accumulated.
        // The other is pushed to the ready-queue which fills up the wraps around
        // (ready-queue is a ring buffer).
        enqueue_and_unlock_chain_wraps_2: "enqueue_and_unlock_chain_wraps-2.json",

        // Two additional reports with unsatisfied dependencies pushed to the ready-queue.
        enqueue_and_unlock_chain_wraps_3: "enqueue_and_unlock_chain_wraps-3.json",

        // Two additional reports, one with no dependencies and thus immediately accumulated.
        // Three old entries in the ready-queue are removed.
        enqueue_and_unlock_chain_wraps_4: "enqueue_and_unlock_chain_wraps-4.json",

        // Report with no dependencies resolves all previous enqueued reports.
        enqueue_and_unlock_chain_wraps_5: "enqueue_and_unlock_chain_wraps-5.json",

        // Report with direct dependency on itself.
        // This makes the report stale, but pushed to the ready-queue anyway.
        enqueue_self_referential_1: "enqueue_self_referential-1.json",

        // Two reports with indirect circular dependency.
        // This makes the reports stale, but pushed to the ready-queue anyway.
        enqueue_self_referential_2: "enqueue_self_referential-2.json",

        // Two reports. First depends on second, which depends on unseen report.
        enqueue_self_referential_3: "enqueue_self_referential-3.json",

        // New report creates a cycle with the previous enqueued reports.
        // This makes the reports stale, but pushed to the ready-queue anyway.
        enqueue_self_referential_4: "enqueue_self_referential-4.json",

        // There are some reports in the ready-queue ready to be accumulated.
        // Even though we don't supply any new available work report theses are processed.
        // This condition may result because of gas exhaustion during previous block execution.
        accumulate_ready_queued_reports_1: "accumulate_ready_queued_reports-1.json",

        // Check that ready-queue and accumulated-reports queues are shifted.
        // A new available report is supplied.
        queues_are_shifted_1: "queues_are_shifted-1.json",

        // Check that ready-queue and accumulated-reports queues are shifted.
        // No new report is supplied.
        queues_are_shifted_2: "queues_are_shifted-2.json",

        // Two reports with unsatisfied dependencies added to the ready-queue.
        ready_queue_editing_1: "ready_queue_editing-1.json",

        // Two reports, one with unsatisfied dependency added to the ready-queue.
        // One accumulated. Ready queue items dependencies are edited.
        ready_queue_editing_2: "ready_queue_editing-2.json",

        // One report unlocks reports in the ready-queue.
        ready_queue_editing_3: "ready_queue_editing-3.json",
    }
}
