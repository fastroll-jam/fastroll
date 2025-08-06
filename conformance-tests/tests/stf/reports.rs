//! Reports state transition conformance tests
use async_trait::async_trait;
use fr_asn_types::types::{common::*, reports::*};
use fr_block::{header_db::BlockHeaderDB, types::block::BlockHeader};
use fr_conformance_tests::{
    err_map::reports::map_error_to_custom_code,
    generate_typed_tests,
    harness::{run_test_case, StateTransitionTest},
};
use fr_crypto::types::Ed25519PubKey;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{
        AccumulateHistory, AccumulateQueue, ActiveSet, AuthPool, BlockHistory, DisputesState,
        EpochEntropy, PastSet, PendingReports, Timeslot,
    },
};
use fr_transition::{
    error::TransitionError,
    state::{reports::transition_reports_update_entries, timeslot::transition_timeslot},
};
use futures::future::join_all;
use std::sync::Arc;

struct ReportsTest;

#[async_trait]
impl StateTransitionTest for ReportsTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/reports/tiny";

    type Input = Input;
    type JamInput = JamInput;
    type State = State;
    type JamTransitionOutput = JamTransitionOutput;
    type Output = Output;
    type ErrorCode = ReportsErrorCode;

    async fn load_pre_state(
        test_pre_state: &Self::State,
        state_manager: Arc<StateManager>,
    ) -> Result<(), StateManagerError> {
        // Convert ASN pre-state into FastRoll types.
        let pre_pending_reports = PendingReports::from(test_pre_state.avail_assignments.clone());
        let pre_active_set = ActiveSet(validators_data_to_validator_set(
            &test_pre_state.curr_validators,
        ));
        let pre_past_set = PastSet(validators_data_to_validator_set(
            &test_pre_state.prev_validators,
        ));
        let pre_entropy = EpochEntropy::from(test_pre_state.entropy.clone());
        let offenders: Vec<Ed25519PubKey> = test_pre_state
            .offenders
            .iter()
            .map(|k| Ed25519PubKey::from(*k))
            .collect();
        let pre_disputes = DisputesState {
            punish_set: offenders,
            ..Default::default()
        };
        let pre_block_history = BlockHistory::from(test_pre_state.recent_blocks.clone());
        let pre_auth_pool = AuthPool::from(test_pre_state.auth_pools.clone());
        let pre_accumulate_queue = AccumulateQueue::default(); // Not included in the test vector but required for GuaranteesXt validation
        let pre_accumulate_history = AccumulateHistory::default(); // Not included in the test vector but required for GuaranteesXt validation
        let pre_accounts: Vec<AccountsMapEntry> = test_pre_state
            .accounts
            .clone()
            .into_iter()
            .map(AccountsMapEntry::from)
            .collect();

        // Load pre-state info the state cache.
        state_manager
            .add_pending_reports(pre_pending_reports)
            .await?;
        state_manager.add_active_set(pre_active_set).await?;
        state_manager.add_past_set(pre_past_set).await?;
        state_manager.add_epoch_entropy(pre_entropy).await?;
        state_manager.add_disputes(pre_disputes).await?;
        state_manager.add_block_history(pre_block_history).await?;
        state_manager.add_auth_pool(pre_auth_pool).await?;
        state_manager
            .add_accumulate_queue(pre_accumulate_queue)
            .await?;
        state_manager
            .add_accumulate_history(pre_accumulate_history)
            .await?;

        for pre_account in pre_accounts {
            state_manager
                .add_account_metadata(pre_account.service_id, pre_account.metadata)
                .await?;
        }

        // Additionally, initialize the timeslot state cache
        state_manager.add_timeslot(Timeslot::new(0)).await?;

        Ok(())
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
        // Convert ASN Input into FastRoll types.
        Ok(JamInput {
            extrinsic: test_input.guarantees.clone().into(),
            timeslot: Timeslot::new(test_input.slot),
        })
    }

    async fn run_state_transition(
        state_manager: Arc<StateManager>,
        header_db: Arc<BlockHeaderDB>,
        _new_header: &mut BlockHeader,
        jam_input: Self::JamInput,
    ) -> Result<Self::JamTransitionOutput, TransitionError> {
        // Run state transitions.
        transition_timeslot(state_manager.clone(), &jam_input.timeslot).await?;

        let (mut reported, mut reporters) = transition_reports_update_entries(
            state_manager,
            header_db,
            &jam_input.extrinsic,
            jam_input.timeslot,
        )
        .await?;

        // Note: Here sorting the output vectors to conform with test vectors. Not part of the GP.
        reported.sort();
        reporters.sort();

        Ok(JamTransitionOutput {
            reported,
            reporters,
        })
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
        let curr_active_set = state_manager.get_active_set().await?;
        let curr_past_set = state_manager.get_past_set().await?;
        let curr_entropy = state_manager.get_epoch_entropy().await?;
        let curr_disputes = state_manager.get_disputes().await?;
        let curr_blocks_history = state_manager.get_block_history().await?;
        let curr_auth_pool = state_manager.get_auth_pool().await?;
        let curr_accounts: Vec<AsnAccountsMapEntry> =
            join_all(pre_state.accounts.iter().map(|s| async {
                let metadata = state_manager
                    .get_account_metadata(s.id)
                    .await
                    .unwrap()
                    .unwrap();
                AsnAccountsMapEntry::from(AccountsMapEntry {
                    service_id: s.id,
                    metadata,
                })
            }))
            .await;

        Ok(State {
            avail_assignments: curr_pending_reports.into(),
            curr_validators: validator_set_to_validators_data(&curr_active_set),
            prev_validators: validator_set_to_validators_data(&curr_past_set),
            entropy: curr_entropy.into(),
            offenders: curr_disputes
                .punish_set
                .into_iter()
                .map(AsnEd25519Key::from)
                .collect(),
            recent_blocks: curr_blocks_history.into(),
            auth_pools: curr_auth_pool.into(),
            accounts: curr_accounts,
        })
    }
}

generate_typed_tests! {
    ReportsTest,

    // Success
    // Report uses current guarantors rotation.
    report_curr_rotation_1: "report_curr_rotation-1.json",

    // Success
    // Report uses previous guarantors rotation.
    report_prev_rotation_1: "report_prev_rotation-1.json",

    // Success
    // Multiple good work reports.
    multiple_reports_1: "multiple_reports-1.json",

    // Fail
    // Context anchor is not recent enough.
    anchor_not_recent_1: "anchor_not_recent-1.json",

    // Fail
    // Context Beefy MMR root doesn't match the one at anchor.
    bad_beefy_mmr_1: "bad_beefy_mmr-1.json",

    // Fail
    // Work digest code hash doesn't match the one expected for the service.
    bad_code_hash_1: "bad_code_hash-1.json",

    // Fail
    // Core index is too big.
    bad_core_index_1: "bad_core_index-1.json",

    // Fail
    // Work digest service identifier doesn't have any associated account in state.
    bad_service_id_1: "bad_service_id-1.json",

    // Fail
    // Context state root doesn't match the one at anchor.
    bad_state_root_1: "bad_state_root-1.json",

    // Fail
    // Validator index is too big.
    bad_validator_index_1: "bad_validator_index-1.json",

    // Fail
    // A core is not available.
    core_engaged_1: "core_engaged-1.json",

    // Fail
    // Prerequisite is missing.
    dependency_missing_1: "dependency_missing-1.json",

    // Fail
    // Package was already available in recent history.
    duplicate_package_in_recent_history_1: "duplicate_package_in_recent_history-1.json",

    // Fail
    // Report contains a duplicate package.
    duplicated_package_in_report_1: "duplicated_package_in_report-1.json",

    // Fail
    // Report refers to a slot in the future with respect to container block slot.
    future_report_slot_1: "future_report_slot-1.json",

    // Fail
    // Invalid report guarantee signature.
    bad_signature_1: "bad_signature-1.json",

    // Success
    // Work report per core gas is very high, still less than the limit.
    high_work_report_gas_1: "high_work_report_gas-1.json",

    // Fail
    // Work report per core gas is too high.
    too_high_work_report_gas_1: "too_high_work_report_gas-1.json",

    // Fail
    // Accumulate gas is below the service minimum.
    service_item_gas_too_low_1: "service_item_gas_too_low-1.json",

    // Success
    // Work report has many dependencies, still less than the limit.
    many_dependencies_1: "many_dependencies-1.json",

    // Fail
    // Work report has too many dependencies.
    too_many_dependencies_1: "too_many_dependencies-1.json",

    // Fail
    // Report with not enough guarantors signatures.
    no_enough_guarantees_1: "no_enough_guarantees-1.json",

    // Fail
    // Target core without any authorizer.
    not_authorized_1: "not_authorized-1.json",

    // Fail
    // Target core with unexpected authorizer.
    not_authorized_2: "not_authorized-2.json",

    // Fail
    // Guarantors indices are not sorted or unique.
    not_sorted_guarantor_1: "not_sorted_guarantor-1.json",

    // Fail
    // Reports cores are not sorted or unique.
    out_of_order_guarantees_1: "out_of_order_guarantees-1.json",

    // Fail
    // Report guarantee slot is too old with respect to block slot.
    report_before_last_rotation_1: "report_before_last_rotation-1.json",

    // Success
    // Simple report dependency satisfied by another work report in the same extrinsic.
    reports_with_dependencies_1: "reports_with_dependencies-1.json",

    // Success
    // Work reports mutual dependency (indirect self-referential dependencies).
    reports_with_dependencies_2: "reports_with_dependencies-2.json",

    // Success
    // Work report direct self-referential dependency.
    reports_with_dependencies_3: "reports_with_dependencies-3.json",

    // Success
    // Work report dependency satisfied by recent blocks history.
    reports_with_dependencies_4: "reports_with_dependencies-4.json",

    // Success
    // Work report segments tree root lookup dependency satisfied
    // by another work report in the same extrinsic.
    reports_with_dependencies_5: "reports_with_dependencies-5.json",

    // Success
    // Work report segments tree root lookup dependency satisfied
    // by recent blocks history.
    reports_with_dependencies_6: "reports_with_dependencies-6.json",

    // Fail
    // Segments tree root lookup item not found in recent blocks history.
    segment_root_lookup_invalid_1: "segment_root_lookup_invalid-1.json",

    // Fail
    // Segments tree root lookup item found in recent blocks history
    // but with an unexpected value.
    segment_root_lookup_invalid_2: "segment_root_lookup_invalid-2.json",

    // Fail
    // Unexpected guarantor for work report core.
    wrong_assignment_1: "wrong_assignment-1.json",

    // Success
    with_avail_assignments_1: "with_avail_assignments-1.json",

    // Success
    // Work report output is very big, still less than the limit.
    big_work_report_output_1: "big_work_report_output-1.json",

    // Fail
    // Work report output size is over the limit.
    too_big_work_report_output_1: "too_big_work_report_output-1.json",
}
