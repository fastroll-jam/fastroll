//! Assurances state transition conformance tests
mod tests {
    use rjam_common::ByteArray;
    use rjam_conformance_tests::{
        asn_types::{assurances::*, common::*},
        err_map::assurances::map_error_to_custom_code,
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use rjam_db::header_db::BlockHeaderDB;
    use rjam_state::StateManager;
    use rjam_transition::{
        error::TransitionError,
        state::{reports::transition_reports_clear_availables, timeslot::transition_timeslot},
    };
    use rjam_types::state::{ActiveSet, PendingReports, Timeslot};

    struct AssurancesTest;

    impl StateTransitionTest for AssurancesTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/assurances/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = JamTransitionOutput;
        type Output = Output;
        type ErrorCode = AssurancesErrorCode;

        fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: &mut StateManager,
        ) -> Result<(), TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let pre_pending_reports =
                PendingReports::from(test_pre_state.avail_assignments.clone());
            let pre_active_set = ActiveSet(validators_data_to_validator_set(
                &test_pre_state.curr_validators,
            ));

            // Load pre-state info the state cache.
            state_manager.add_pending_reports(pre_pending_reports)?;
            state_manager.add_active_set(pre_active_set)?;
            // Additionally, initialize the timeslot state cache
            state_manager.add_timeslot(Timeslot::new(0))?;

            // Commit the pre-state into the DB
            state_manager.commit_dirty_cache()?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            Ok(JamInput {
                extrinsic: test_input.assurances.clone().into(),
                timeslot: Timeslot::new(test_input.slot),
                parent_hash: ByteArray::new(test_input.parent.0),
            })
        }

        fn run_state_transition(
            state_manager: &StateManager,
            _header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // Run state transitions.
            transition_timeslot(state_manager, &jam_input.timeslot)?;

            let removed_reports = transition_reports_clear_availables(
                state_manager,
                &jam_input.extrinsic,
                &jam_input.parent_hash,
            )?;

            Ok(JamTransitionOutput { removed_reports })
        }

        fn map_error_code(e: TransitionError) -> Self::ErrorCode {
            map_error_to_custom_code(e)
        }

        fn extract_output(
            _header_db: &BlockHeaderDB,
            transition_output: Option<&Self::JamTransitionOutput>,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            if let Some(error_code) = error_code {
                return Output::err(error_code.clone());
            }

            // Convert RJAM output into ASN Output.
            Output::ok(transition_output.cloned().unwrap().into())
        }

        fn extract_post_state(
            state_manager: &StateManager,
            pre_state: &Self::State,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::State {
            if error_code.is_some() {
                // Rollback state transition
                return pre_state.clone();
            }

            // Get the posterior state from the state cache.
            let curr_pending_reports = state_manager.get_pending_reports().unwrap();
            let curr_active_set = state_manager.get_active_set().unwrap();

            State {
                avail_assignments: curr_pending_reports.into(),
                curr_validators: validator_set_to_validators_data(&curr_active_set),
            }
        }
    }

    generate_typed_tests! {
        AssurancesTest,

        // FIXME: Signature verification failure
        // Success
        // Progress with an empty assurances extrinsic.
        // assurance_for_not_engaged_core_1: "assurance_for_not_engaged_core-1.json",

        // Success
        // Several assurances contributing to establishing availability super-majority for some of the cores.
        assurance_with_bad_attestation_parent_1: "assurance_with_bad_attestation_parent-1.json",

        // FIXME: Signature verification failure
        // Success
        // Progress with an empty assurances extrinsic.
        // Stale work report assignment is removed (but not returned in the output).
        // assurances_for_stale_report_1: "assurances_for_stale_report-1.json",

        // Fail
        // One assurance has a bad signature.
        assurances_with_bad_signature_1: "assurances_with_bad_signature-1.json",

        // TODO: check - this test vector also returns err(not_sorted_or_unique_assurers)
        // Fail
        // One assurance has a bad validator index.
        // assurances_with_bad_validator_index_1: "assurances_with_bad_validator_index-1.json",

        // Fail
        // One assurance targets a core without any assigned work report.
        assurers_not_sorted_or_unique_1: "assurers_not_sorted_or_unique-1.json",

        // Fail
        // One assurance has a bad attestation parent hash.
        assurers_not_sorted_or_unique_2: "assurers_not_sorted_or_unique-2.json",

        // Fail
        // One assurance targets a core with a stale report.
        // We are lenient on the stale report as far as it is available.
        no_assurances_1: "no_assurances-1.json",

        // Fail
        // Assurers not sorted.
        no_assurances_with_stale_report_1: "no_assurances_with_stale_report-1.json",

        // FIXME: Signature verification failure
        // Fail
        // Duplicate assurer.
        // some_assurances_1: "some_assurances-1.json",
    }
}
