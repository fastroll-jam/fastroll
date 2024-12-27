//! Assurances state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        asn_types::{validator_set_to_validators_data, validators_data_to_validator_set},
        generate_typed_tests,
        state_transition::{
            assurances::{
                asn_types::{
                    AssurancesErrorCode, Input, JamInput, JamTransitionOutput, Output, State,
                },
                utils::map_error_to_custom_code,
            },
            state_transition_test::{run_test_case, StateTransitionTest},
        },
    };
    use rjam_common::ByteArray;
    use rjam_db::BlockHeaderDB;
    use rjam_state::StateManager;
    use rjam_transition::{
        error::TransitionError,
        state::{reports::transition_reports_clear_availables, timeslot::transition_timeslot},
    };
    use rjam_types::{
        state::{ActiveSet, PendingReports, Timeslot},
        state_utils::{StateEntryType, StateKeyConstant},
    };

    struct AssurancesTest;

    impl StateTransitionTest for AssurancesTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/assurances/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = JamTransitionOutput;
        type Output = Output;
        type ErrorCode = AssurancesErrorCode;

        fn setup_state_manager(
            test_pre_state: &Self::State,
        ) -> Result<StateManager, TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let prior_pending_reports =
                PendingReports::from(test_pre_state.avail_assignments.clone());
            let prior_active_set = ActiveSet(validators_data_to_validator_set(
                &test_pre_state.curr_validators,
            ));

            // Initialize StateManager.
            let mut state_manager = StateManager::new_for_test();

            // Load pre-state info the state cache.
            state_manager.load_state_for_test(
                StateKeyConstant::PendingReports,
                StateEntryType::PendingReports(prior_pending_reports),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::ActiveSet,
                StateEntryType::ActiveSet(prior_active_set),
            );

            // Additionally, initialize the timeslot state cache
            state_manager.load_state_for_test(
                StateKeyConstant::Timeslot,
                StateEntryType::Timeslot(Timeslot::new(0)),
            );

            Ok(state_manager)
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
            let current_pending_reports = state_manager.get_pending_reports().unwrap();
            let current_active_set = state_manager.get_active_set().unwrap();

            State {
                avail_assignments: current_pending_reports.into(),
                curr_validators: validator_set_to_validators_data(&current_active_set),
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
