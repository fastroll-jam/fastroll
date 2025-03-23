//! Accumulate state transition conformance tests
#![allow(unused_imports)]
mod tests {
    use async_trait::async_trait;
    use futures::future::join_all;
    use rjam_block::header_db::BlockHeaderDB;
    use rjam_common::{workloads::WorkReport, Hash32};
    use rjam_conformance_tests::{
        asn_types::{
            accumulate::*,
            common::{AsnOpaqueHash, AsnServiceInfo},
            preimages::{AsnPreimagesMapEntry, PreimagesMapEntry},
        },
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use rjam_pvm_invocation::pipeline::{
        accumulate_result_commitment, utils::collect_accumulatable_reports,
    };
    use rjam_state::{
        error::StateManagerError,
        manager::StateManager,
        types::{
            AccountMetadata, AccumulateHistory, AccumulateQueue, EpochEntropy, PrivilegedServices,
            Timeslot,
        },
    };
    use rjam_transition::{
        error::TransitionError,
        state::{
            accumulate::{transition_accumulate_history, transition_accumulate_queue},
            services::transition_on_accumulate,
            timeslot::transition_timeslot,
        },
    };
    use std::{collections::HashSet, sync::Arc};

    struct AccumulateTest;

    #[async_trait]
    impl StateTransitionTest for AccumulateTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/accumulate/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = JamTransitionOutput;
        type Output = Output;
        type ErrorCode = AccumulateErrorCode;
        async fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: Arc<StateManager>,
        ) -> Result<(), StateManagerError> {
            // Convert ASN pre-state into RJAM types.
            let pre_timeslot = Timeslot::new(test_pre_state.slot);
            // TODO: why do we need entropy here?
            let pre_entropy = EpochEntropy([
                Hash32::from(test_pre_state.entropy),
                Hash32::default(),
                Hash32::default(),
                Hash32::default(),
            ]);
            let pre_acc_queue = AccumulateQueue::from(test_pre_state.ready_queue.clone());
            let pre_acc_history = AccumulateHistory::from(test_pre_state.accumulated.clone());
            let pre_privileged_services =
                PrivilegedServices::from(test_pre_state.privileges.clone());

            // Load pre-state info the state cache.
            state_manager.add_timeslot(pre_timeslot).await?;
            state_manager.add_epoch_entropy(pre_entropy).await?;
            state_manager.add_accumulate_queue(pre_acc_queue).await?;
            state_manager
                .add_accumulate_history(pre_acc_history)
                .await?;

            // Add service info for privileged services
            let mut privileged_service_ids = HashSet::new();
            privileged_service_ids.insert(pre_privileged_services.manager_service);
            privileged_service_ids.insert(pre_privileged_services.assign_service);
            privileged_service_ids.insert(pre_privileged_services.designate_service);
            for privileged_service_id in privileged_service_ids {
                state_manager
                    .add_account_metadata(privileged_service_id, AccountMetadata::default())
                    .await?;
            }
            state_manager
                .add_privileged_services(pre_privileged_services)
                .await?;

            // Add regular accounts
            for account in &test_pre_state.accounts {
                // Add service info
                state_manager
                    .add_account_metadata(
                        account.id,
                        AccountMetadata::from(account.data.service.clone()),
                    )
                    .await?;
                // Add preimages entries
                for preimage in &account.data.preimages {
                    let key = Hash32::from(preimage.hash);
                    let val = PreimagesMapEntry::from(preimage.clone()).data;
                    state_manager
                        .add_account_preimages_entry(account.id, &key, val)
                        .await?;
                }
            }

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            Ok(JamInput {
                slot: Timeslot::new(test_input.slot),
                reports: test_input
                    .reports
                    .clone()
                    .into_iter()
                    .map(WorkReport::from)
                    .collect(),
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            _header_db: &mut BlockHeaderDB,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // Run state transitions.
            transition_timeslot(state_manager.clone(), &jam_input.slot).await?;
            let pre_timeslot = state_manager.get_timeslot_clean().await?;
            let curr_timeslot = state_manager.get_timeslot().await?;
            let pre_accumulate_queue = state_manager.get_accumulate_queue().await?;
            let pre_accumulate_history = state_manager.get_accumulate_history().await?;
            let (accumulatable_reports, queued_reports) = collect_accumulatable_reports(
                jam_input.reports,
                &pre_accumulate_queue,
                &pre_accumulate_history,
                curr_timeslot.slot(),
            );
            let acc_summary =
                transition_on_accumulate(state_manager.clone(), &accumulatable_reports).await?;
            transition_accumulate_history(
                state_manager.clone(),
                &accumulatable_reports,
                acc_summary.accumulated_reports_count,
            )
            .await?;
            transition_accumulate_queue(
                state_manager,
                &queued_reports,
                pre_timeslot,
                curr_timeslot,
            )
            .await?;

            Ok(JamTransitionOutput {
                accumulate_root: accumulate_result_commitment(acc_summary.output_pairs),
            })
        }

        fn map_error_code(_e: TransitionError) -> Self::ErrorCode {
            // Not specifying the exact error type for now
            AccumulateErrorCode::reserved
        }

        fn extract_output(
            _header_db: &BlockHeaderDB,
            transition_output: Option<&Self::JamTransitionOutput>,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            if error_code.is_some() {
                return Output::err;
            }

            Output::ok(AsnOpaqueHash::from(
                transition_output.unwrap().accumulate_root,
            ))
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
            let curr_timeslot = state_manager.get_timeslot().await?;
            let curr_entropy = state_manager.get_epoch_entropy().await?.current();
            let curr_acc_queue = state_manager.get_accumulate_queue().await?;
            let curr_acc_history = state_manager.get_accumulate_history().await?;
            let curr_privileged_services = state_manager.get_privileged_services().await?;
            let curr_accounts = join_all(pre_state.accounts.iter().map(|s| async {
                let curr_metadata = AsnServiceInfo::from(
                    state_manager
                        .get_account_metadata(s.id)
                        .await
                        .unwrap()
                        .unwrap(),
                );

                let curr_preimages = join_all(s.data.preimages.iter().map(|e| async {
                    // Get the key from the pre-state
                    let key = Hash32::from(e.hash);
                    // Get the posterior preimage value
                    let preimage = state_manager
                        .get_account_preimages_entry(s.id, &key)
                        .await
                        .unwrap()
                        .unwrap();
                    AsnPreimagesMapEntry::from(PreimagesMapEntry {
                        key,
                        data: preimage,
                    })
                }))
                .await;

                AsnAccountsMapEntry {
                    id: s.id,
                    data: AsnAccount {
                        service: curr_metadata,
                        preimages: curr_preimages,
                    },
                }
            }))
            .await;

            Ok(State {
                slot: curr_timeslot.slot(),
                entropy: curr_entropy.into(),
                ready_queue: curr_acc_queue.into(),
                accumulated: curr_acc_history.into(),
                privileges: curr_privileged_services.into(),
                accounts: curr_accounts,
            })
        }
    }

    // generate_typed_tests! {
    //     AccumulateTest,
    //
    //     // No reports.
    //     no_available_reports_1: "no_available_reports-1.json",
    //
    //     // Report with no dependencies.
    //     process_one_immediate_report_1: "process_one_immediate_report-1.json",
    //
    //     // Report with unsatisfied dependency added to the ready-queue.
    //     enqueue_and_unlock_simple_1: "enqueue_and_unlock_simple-1.json",
    //
    //     // Report with no dependencies that resolves previous dependency.
    //     enqueue_and_unlock_simple_2: "enqueue_and_unlock_simple-2.json",
    //
    //     // Report with unsatisfied segment tree root dependency added to the ready-queue.
    //     enqueue_and_unlock_with_sr_lookup_1: "enqueue_and_unlock_with_sr_lookup-1.json",
    //
    //     // Report with no dependencies that resolves previous dependency.
    //     enqueue_and_unlock_with_sr_lookup_2: "enqueue_and_unlock_with_sr_lookup-2.json",
    //
    //     // Two reports with unsatisfied dependencies added to the ready-queue.
    //     enqueue_and_unlock_chain_1: "enqueue_and_unlock_chain-1.json",
    //
    //     // Two additional reports with unsatisfied dependencies added to the ready-queue.
    //     enqueue_and_unlock_chain_2: "enqueue_and_unlock_chain-2.json",
    //
    //     // Two additional reports. One with unsatisfied dependencies, thus added to the ready-queue.
    //     // One report is accumulated and resolves two previously enqueued reports.
    //     enqueue_and_unlock_chain_3: "enqueue_and_unlock_chain-3.json",
    //
    //     // Report that resolves all remaining queued dependencies.
    //     enqueue_and_unlock_chain_4: "enqueue_and_unlock_chain-4.json",
    //
    //     // Two reports with unsatisfied dependencies added to the ready-queue.
    //     enqueue_and_unlock_chain_wraps_1: "enqueue_and_unlock_chain_wraps-1.json",
    //
    //     // Two additional reports, one with no dependencies and thus immediately accumulated.
    //     // The other is pushed to the ready-queue which fills up the wraps around
    //     // (ready-queue is a ring buffer).
    //     enqueue_and_unlock_chain_wraps_2: "enqueue_and_unlock_chain_wraps-2.json",
    //
    //     // Two additional reports with unsatisfied dependencies pushed to the ready-queue.
    //     enqueue_and_unlock_chain_wraps_3: "enqueue_and_unlock_chain_wraps-3.json",
    //
    //     // Two additional reports, one with no dependencies and thus immediately accumulated.
    //     // Three old entries in the ready-queue are removed.
    //     enqueue_and_unlock_chain_wraps_4: "enqueue_and_unlock_chain_wraps-4.json",
    //
    //     // Report with no dependencies resolves all previous enqueued reports.
    //     enqueue_and_unlock_chain_wraps_5: "enqueue_and_unlock_chain_wraps-5.json",
    //
    //     // Report with direct dependency on itself.
    //     // This makes the report stale, but pushed to the ready-queue anyway.
    //     enqueue_self_referential_1: "enqueue_self_referential-1.json",
    //
    //     // Two reports with indirect circular dependency.
    //     // This makes the reports stale, but pushed to the ready-queue anyway.
    //     enqueue_self_referential_2: "enqueue_self_referential-2.json",
    //
    //     // Two reports. First depends on second, which depends on unseen report.
    //     enqueue_self_referential_3: "enqueue_self_referential-3.json",
    //
    //     // New report creates a cycle with the previous enqueued reports.
    //     // This makes the reports stale, but pushed to the ready-queue anyway.
    //     enqueue_self_referential_4: "enqueue_self_referential-4.json",
    //
    //     // There are some reports in the ready-queue ready to be accumulated.
    //     // Even though we don't supply any new available work report theses are processed.
    //     // This condition may result because of gas exhaustion during previous block execution.
    //     accumulate_ready_queued_reports_1: "accumulate_ready_queued_reports-1.json",
    //
    //     // Check that ready-queue and accumulated-reports queues are shifted.
    //     // A new available report is supplied.
    //     queues_are_shifted_1: "queues_are_shifted-1.json",
    //
    //     // Check that ready-queue and accumulated-reports queues are shifted.
    //     // No new report is supplied.
    //     queues_are_shifted_2: "queues_are_shifted-2.json",
    //
    //     // Two reports with unsatisfied dependencies added to the ready-queue.
    //     ready_queue_editing_1: "ready_queue_editing-1.json",
    //
    //     // Two reports, one with unsatisfied dependency added to the ready-queue.
    //     // One accumulated. Ready queue items dependencies are edited.
    //     ready_queue_editing_2: "ready_queue_editing-2.json",
    //
    //     // One report unlocks reports in the ready-queue.
    //     ready_queue_editing_3: "ready_queue_editing-3.json",
    // }
}
