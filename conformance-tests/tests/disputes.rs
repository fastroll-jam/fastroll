//! Disputes state transition conformance tests
mod disputes {
    use async_trait::async_trait;
    use rjam_block::{
        header_db::BlockHeaderDB, types::extrinsics::disputes::OffendersHeaderMarker,
    };
    use rjam_conformance_tests::{
        asn_types::{common::*, disputes::*},
        err_map::disputes::map_error_to_custom_code,
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use rjam_state::{
        error::StateManagerError,
        manager::StateManager,
        types::{ActiveSet, DisputesState, PastSet, PendingReports, Timeslot},
    };
    use rjam_transition::{
        error::TransitionError,
        state::{disputes::transition_disputes, reports::transition_reports_eliminate_invalid},
    };
    use std::sync::Arc;

    struct DisputesTest;

    #[async_trait]
    impl StateTransitionTest for DisputesTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/disputes/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = ();
        type Output = Output;
        type ErrorCode = DisputesErrorCode;

        async fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: Arc<StateManager>,
        ) -> Result<(), StateManagerError> {
            // Convert ASN pre-state into RJAM types.
            let pre_disputes = DisputesState::from(test_pre_state.psi.clone());
            let pre_pending_reports = PendingReports::from(test_pre_state.rho.clone());
            let pre_timeslot = Timeslot::new(test_pre_state.tau);
            let pre_active_set = ActiveSet(validators_data_to_validator_set(&test_pre_state.kappa));
            let pre_past_set = PastSet(validators_data_to_validator_set(&test_pre_state.lambda));

            // Load pre-state info the state cache.
            state_manager.add_disputes(pre_disputes).await?;
            state_manager
                .add_pending_reports(pre_pending_reports)
                .await?;
            state_manager.add_timeslot(pre_timeslot).await?;
            state_manager.add_active_set(pre_active_set).await?;
            state_manager.add_past_set(pre_past_set).await?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            Ok(JamInput {
                extrinsic: test_input.disputes.clone().into(),
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            let pre_timeslot = state_manager.get_timeslot().await?;
            let disputes = jam_input.extrinsic;
            let offenders_marker = disputes.collect_offender_keys();

            // Run state transitions.
            transition_reports_eliminate_invalid(state_manager.clone(), &disputes, pre_timeslot)
                .await?;
            transition_disputes(state_manager, &disputes, pre_timeslot).await?;
            header_db.set_offenders_marker(&offenders_marker)?;

            Ok(())
        }

        fn map_error_code(e: TransitionError) -> Self::ErrorCode {
            map_error_to_custom_code(e)
        }

        fn extract_output(
            header_db: &BlockHeaderDB,
            _transition_output: Option<&Self::JamTransitionOutput>,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            if let Some(error_code) = error_code {
                return Output::err(error_code.clone());
            }

            // Convert RJAM output into ASN Output.
            let curr_header_offenders_marker =
                header_db.get_staging_header().unwrap().offenders_marker;
            let curr_offenders_marker = OffendersHeaderMarker {
                items: curr_header_offenders_marker,
            };
            let disputes_output_marks: AsnDisputesOutputMarks = curr_offenders_marker.into();

            Output::ok(disputes_output_marks)
        }

        async fn extract_post_state(
            state_manager: Arc<StateManager>,
            pre_state: &Self::State,
            error_code: &Option<Self::ErrorCode>,
        ) -> Result<Self::State, StateManagerError> {
            if error_code.is_some() {
                // Rollback state transition
                return Ok(pre_state.clone());
            }

            // Get the posterior state from the state cache.
            let curr_disputes_state = state_manager.get_disputes().await?;
            let curr_pending_reports = state_manager.get_pending_reports().await?;
            let curr_timeslot = state_manager.get_timeslot().await?;
            let curr_active_set = state_manager.get_active_set().await?;
            let curr_past_set = state_manager.get_past_set().await?;

            Ok(State {
                psi: curr_disputes_state.into(),
                rho: curr_pending_reports.into(),
                tau: curr_timeslot.0,
                kappa: validator_set_to_validators_data(&curr_active_set),
                lambda: validator_set_to_validators_data(&curr_past_set),
            })
        }
    }

    generate_typed_tests! {
        DisputesTest,

        // Success
        // No verdicts, nothing special happens.
        progress_with_no_verdicts_1: "progress_with_no_verdicts-1.json",

        // Fail
        // Not sorted work reports within a verdict.
        progress_with_verdicts_1: "progress_with_verdicts-1.json",

        // Fail
        // Not unique votes within a verdict.
        progress_with_verdicts_2: "progress_with_verdicts-2.json",

        // Fail
        // Not sorted, valid verdicts.
        progress_with_verdicts_3: "progress_with_verdicts-3.json",

        // Success
        // Sorted, valid verdicts.
        progress_with_verdicts_4: "progress_with_verdicts-4.json",

        // Fail
        // Not homogeneous judgements, but positive votes count is not correct.
        progress_with_verdicts_5: "progress_with_verdicts-5.json",

        // Success
        // Not homogeneous judgements, results in wonky verdict.
        progress_with_verdicts_6: "progress_with_verdicts-6.json",

        // Fail
        // Missing culprits for bad verdict.
        progress_with_culprits_1: "progress_with_culprits-1.json",

        // Fail
        // Single culprit for bad verdict.
        progress_with_culprits_2: "progress_with_culprits-2.json",

        // Fail
        // Two culprits for bad verdict, not sorted.
        progress_with_culprits_3: "progress_with_culprits-3.json",

        // Success
        // Two culprits for bad verdict, sorted.
        progress_with_culprits_4: "progress_with_culprits-4.json",

        // Fail
        // Report an already recorded verdict, with culprits.
        progress_with_culprits_5: "progress_with_culprits-5.json",

        // Fail
        // Culprit offender already in the offenders list.
        progress_with_culprits_6: "progress_with_culprits-6.json",

        // Fail
        // Offender relative to a not present verdict.
        progress_with_culprits_7: "progress_with_culprits-7.json",

        // Fail
        // Missing faults for good verdict.
        progress_with_faults_1: "progress_with_faults-1.json",

        // Success
        // One fault offender for good verdict.
        progress_with_faults_2: "progress_with_faults-2.json",

        // Fail
        // Two fault offenders for a good verdict, not sorted.
        progress_with_faults_3: "progress_with_faults-3.json",

        // Success
        // Two fault offenders for a good verdict, sorted.
        progress_with_faults_4: "progress_with_faults-4.json",

        // Fail
        // Report an already recorded verdict, with faults.
        progress_with_faults_5: "progress_with_faults-5.json",

        // Fail
        // Fault offender already in the offenders list.
        progress_with_faults_6: "progress_with_faults-6.json",

        // Fail
        // Auditor marked as offender, but vote matches the verdict.
        progress_with_faults_7: "progress_with_faults-7.json",

        // Success
        // Invalidation of availability assignments.
        progress_invalidates_avail_assignments_1: "progress_invalidates_avail_assignments-1.json",

        // Fail
        // Bad signature within the verdict judgements.
        progress_with_bad_signatures_1: "progress_with_bad_signatures-1.json",

        // TODO: This case also throws `already_judged` and `culprits_not_sorted_unique`.
        // Fail
        // Bad signature within the culprits sequence.
        // progress_with_bad_signatures_2: "progress_with_bad_signatures-2.json",

        // Fail
        // Unexpected key found in the culprits sequence.
        progress_with_invalid_keys_1: "progress_with_invalid_keys-1.json",

        // Fail
        // Unexpected key found in the faults sequence
        progress_with_invalid_keys_2: "progress_with_invalid_keys-2.json",

        // Success
        // Use previous epoch validators set for verdict signatures verification.
        progress_with_verdict_signatures_from_previous_set_1: "progress_with_verdict_signatures_from_previous_set-1.json",

        // Fail
        // Age too old for verdicts judgements.
        progress_with_verdict_signatures_from_previous_set_2: "progress_with_verdict_signatures_from_previous_set-2.json",
    }
}
