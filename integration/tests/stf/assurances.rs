//! Assurances state transition integration tests
use async_trait::async_trait;
use fr_asn_types::assurances::*;
use fr_block::{header_db::BlockHeaderDB, types::block::BlockHeader};
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{ActiveSet, PendingReports, Timeslot},
};
use fr_test_utils::{
    err_map::assurances::map_error_to_custom_code,
    generate_typed_tests,
    stf_harness::{run_test_case, StateTransitionTest},
};
use fr_transition::{
    error::TransitionError,
    state::{reports::transition_reports_clear_availables, timeslot::transition_timeslot},
};
use std::sync::Arc;

struct AssurancesTest;

#[async_trait]
impl StateTransitionTest for AssurancesTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/assurances";

    type Input = Input;
    type JamInput = JamInput;
    type State = State;
    type JamTransitionOutput = JamTransitionOutput;
    type Output = Output;
    type ErrorCode = AssurancesErrorCode;

    async fn load_pre_state(
        test_pre_state: &Self::State,
        state_manager: Arc<StateManager>,
    ) -> Result<(), StateManagerError> {
        // Convert ASN pre-state into FastRoll types.
        let pre_pending_reports = PendingReports::from(test_pre_state.avail_assignments.clone());
        let pre_active_set = ActiveSet(test_pre_state.curr_validators.clone().into());
        let posterior_active_set = ActiveSet(test_pre_state.post_validators.clone().into());

        // Load pre-state info the state cache.
        state_manager
            .add_pending_reports(pre_pending_reports)
            .await?;
        state_manager.add_active_set(pre_active_set).await?;
        // `κ'` replaces the working value, while `κ` stays as the clean prior value.
        state_manager
            .with_mut_active_set(
                StateMut::Update,
                |active_set| -> Result<(), StateManagerError> {
                    *active_set = posterior_active_set;
                    Ok(())
                },
            )
            .await?;
        // Additionally, initialize the timeslot state cache
        state_manager.add_timeslot(Timeslot::new(0)).await?;

        Ok(())
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
        // Convert ASN Input into FastRoll types.
        Ok(JamInput {
            extrinsic: test_input.assurances.clone().into(),
            timeslot: Timeslot::new(test_input.slot),
            parent_hash: test_input.parent.clone(),
        })
    }

    async fn run_state_transition(
        state_manager: Arc<StateManager>,
        _header_db: Arc<BlockHeaderDB>,
        _new_header: &mut BlockHeader,
        jam_input: Self::JamInput,
    ) -> Result<Self::JamTransitionOutput, TransitionError> {
        // Run state transitions.
        transition_timeslot(state_manager.clone(), &jam_input.timeslot).await?;

        let removed_reports = transition_reports_clear_availables(
            state_manager,
            &jam_input.extrinsic,
            jam_input.parent_hash,
        )
        .await?;

        Ok(JamTransitionOutput { removed_reports })
    }

    fn map_error_code(e: TransitionError) -> Self::ErrorCode {
        map_error_to_custom_code(e)
    }

    fn extract_output(
        _new_header: &BlockHeader,
        transition_output: Option<&Self::JamTransitionOutput>,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output {
        if let Some(error_code) = error_code {
            return Output::err(error_code.clone());
        }

        // Convert FastRoll output into ASN Output.
        Output::ok(transition_output.cloned().unwrap().into())
    }

    async fn extract_post_state(
        state_manager: Arc<StateManager>,
        pre_state: &Self::State,
        _test_case_post_state: &Self::State,
        error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError> {
        if error_code.is_some() {
            // Rollback state transition
            return Ok(pre_state.clone());
        }

        // Get the posterior state from the state cache.
        let curr_pending_reports = state_manager.get_pending_reports().await?;
        let prior_active_set = state_manager.get_active_set_clean().await?;
        let posterior_active_set = state_manager.get_active_set().await?;

        Ok(State {
            avail_assignments: curr_pending_reports.into(),
            curr_validators: prior_active_set.0.into(),
            post_validators: posterior_active_set.0.into(),
        })
    }
}

generate_typed_tests! {
    AssurancesTest,

    // Success
    // Progress with an empty assurances extrinsic.
    #[ignore = "GP 0.8.0 not implemented"]
    no_assurances_1: "no_assurances-1.json",

    // Success
    // Several assurances contributing to establishing availability super-majority for some of the cores.
    #[ignore = "GP 0.8.0 not implemented"]
    some_assurances_1: "some_assurances-1.json",

    // Success
    // Progress with an empty assurances extrinsic.
    // Stale work report assignment is removed (but not returned in the output).
    #[ignore = "GP 0.8.0 not implemented"]
    no_assurances_with_stale_report_1: "no_assurances_with_stale_report-1.json",

    // Fail
    // One assurance has a bad signature.
    #[ignore = "GP 0.8.0 not implemented"]
    assurances_with_bad_signature_1: "assurances_with_bad_signature-1.json",

    // TODO: Test: - this test vector also returns err(not_sorted_or_unique_assurers)
    // Fail
    // One assurance has a bad validator index.
    #[ignore = "the vector also hits not_sorted_or_unique_assurers, see the TODO above"]
    assurances_with_bad_validator_index_1: "assurances_with_bad_validator_index-1.json",

    // Fail
    // One assurance targets a core without any assigned work report.
    #[ignore = "GP 0.8.0 not implemented"]
    assurance_for_not_engaged_core_1: "assurance_for_not_engaged_core-1.json",

    // Fail
    // One assurance has a bad attestation parent hash.
    #[ignore = "GP 0.8.0 not implemented"]
    assurance_with_bad_attestation_parent_1: "assurance_with_bad_attestation_parent-1.json",

    // Fail
    // One assurance targets a core with a stale report.
    // We are lenient on the stale report as far as it is available.
    #[ignore = "GP 0.8.0 not implemented"]
    assurances_for_stale_report_1: "assurances_for_stale_report-1.json",

    // Fail
    // Assurers not sorted.
    #[ignore = "GP 0.8.0 not implemented"]
    assurers_not_sorted_or_unique_1: "assurers_not_sorted_or_unique-1.json",

    // Fail
    // Duplicate assurer.
    #[ignore = "GP 0.8.0 not implemented"]
    assurers_not_sorted_or_unique_2: "assurers_not_sorted_or_unique-2.json",

    // Success
    // Posterior active validators set is smaller than the prior one.
    // Assurances, signed by the prior set, make the core 0 report available. Every other pending report is cleared.
    #[ignore = "GP 0.8.0 not implemented"]
    val_set_size_change_clears_pending_reports_1: "val_set_size_change_clears_pending_reports-1.json",
}
