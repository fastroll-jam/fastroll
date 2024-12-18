//! Disputes state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        asn_types::{validator_set_to_validators_data, validators_data_to_validator_set},
        disputes::{
            asn_types::{DisputesOutputMarks, Input, Output, State, TestCase},
            utils::map_error_to_custom_code,
        },
        generate_tests,
        test_utils::load_test_case,
    };
    use rjam_db::BlockHeaderDB;
    use rjam_state::{StateEntryType, StateKeyConstant, StateManager};
    use rjam_transition::{
        error::TransitionError,
        header::set_header_offenders_marker,
        state::{disputes::transition_disputes, reports::transition_reports_eliminate_invalid},
    };
    use rjam_types::{
        extrinsics::disputes::{DisputesExtrinsic, OffendersHeaderMarker},
        state::{
            disputes::DisputesState,
            reports::PendingReports,
            timeslot::Timeslot,
            validators::{ActiveSet, PastSet},
        },
    };
    use std::path::PathBuf;

    const PATH_PREFIX: &str = "jamtestvectors-disputes/disputes/tiny";

    // Returns the actual post state, to be compared with the test post state.
    fn run_state_transition(
        test_input: &Input,
        test_pre_state: &State,
    ) -> Result<(State, Output), TransitionError> {
        // Convert ASN pre-state into RJAM types.
        let prior_disputes_state = DisputesState::from(test_pre_state.psi.clone());
        let prior_pending_reports = PendingReports::from(test_pre_state.rho.clone());
        let prior_timeslot = Timeslot::new(test_pre_state.tau);
        let prior_active_set = ActiveSet(validators_data_to_validator_set(&test_pre_state.kappa));
        let prior_past_set = PastSet(validators_data_to_validator_set(&test_pre_state.lambda));

        // Initialize StateManager.
        let mut state_manager = StateManager::new_for_test();
        // Initialize HeaderDB.
        let mut header_db = BlockHeaderDB::initialize_for_test();

        // Load pre-state info the state cache.
        state_manager.load_state_for_test(
            StateKeyConstant::DisputesState,
            StateEntryType::DisputesState(prior_disputes_state),
        );
        state_manager.load_state_for_test(
            StateKeyConstant::PendingReports,
            StateEntryType::PendingReports(prior_pending_reports),
        );
        state_manager.load_state_for_test(
            StateKeyConstant::Timeslot,
            StateEntryType::Timeslot(prior_timeslot),
        );
        state_manager.load_state_for_test(
            StateKeyConstant::ActiveSet,
            StateEntryType::ActiveSet(prior_active_set),
        );
        state_manager.load_state_for_test(
            StateKeyConstant::PastSet,
            StateEntryType::PastSet(prior_past_set),
        );

        // Convert ASN Input into RJAM types.
        let input_extrinsic: DisputesExtrinsic = test_input.disputes.clone().into();

        // Run state transitions.
        let offenders_marker = input_extrinsic.collect_offender_keys();
        transition_reports_eliminate_invalid(&state_manager, &input_extrinsic, &prior_timeslot)?;
        transition_disputes(&state_manager, &input_extrinsic, &prior_timeslot)?;
        set_header_offenders_marker(&mut header_db, &offenders_marker.items)?;

        // Convert RJAM output into ASN Output.
        let current_header_offenders_marker = header_db
            .get_staging_header()
            .cloned()
            .unwrap()
            .offenders_marker;
        let current_offenders_marker = OffendersHeaderMarker {
            items: current_header_offenders_marker,
        };
        let disputes_output_marks: DisputesOutputMarks = current_offenders_marker.into();

        // Get the posterior state from the state cache.
        let current_disputes_state = state_manager.get_disputes()?;
        let current_pending_reports = state_manager.get_pending_reports()?;
        let current_timeslot = state_manager.get_timeslot()?;
        let current_active_set = state_manager.get_active_set()?;
        let current_past_set = state_manager.get_past_set()?;

        let post_state = State {
            psi: current_disputes_state.into(),
            rho: current_pending_reports.into(),
            tau: current_timeslot.0,
            kappa: validator_set_to_validators_data(&current_active_set),
            lambda: validator_set_to_validators_data(&current_past_set),
        };

        Ok((post_state, Output::ok(disputes_output_marks)))
    }

    fn run_state_transition_with_error_mapping(
        test_input: &Input,
        test_pre_state: &State,
    ) -> Result<(State, Output), TransitionError> {
        run_state_transition(test_input, test_pre_state).or_else(|e| {
            // Rollback on failure
            Ok((
                test_pre_state.clone(),
                Output::err(map_error_to_custom_code(e)),
            ))
        })
    }

    fn run_test_case(filename: &str) -> Result<(), TransitionError> {
        let path = PathBuf::from(PATH_PREFIX).join(filename);
        let test_case: TestCase = load_test_case(&path).expect("Failed to load test vector.");
        let expected_post_state = test_case.post_state;

        let (post_state, output) =
            run_state_transition_with_error_mapping(&test_case.input, &test_case.pre_state)?;

        // Assertion on the post state
        // assert_eq!(post_state, expected_post_state);
        assert_eq!(post_state.psi, expected_post_state.psi);
        assert_eq!(post_state.rho, expected_post_state.rho);
        assert_eq!(post_state.tau, expected_post_state.tau);
        assert_eq!(post_state.kappa, expected_post_state.kappa);
        assert_eq!(post_state.lambda, expected_post_state.lambda);

        // Assertion on the state transition output
        assert_eq!(output, test_case.output);
        Ok(())
    }

    generate_tests! {
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

        // Success
        // Use previous epoch validators set for verdict signatures verification.
        progress_with_verdict_signatures_from_previous_set_1: "progress_with_verdict_signatures_from_previous_set-1.json",

        // Fail
        // Age too old for verdicts judgements.
        progress_with_verdict_signatures_from_previous_set_2: "progress_with_verdict_signatures_from_previous_set-2.json",
    }
}
