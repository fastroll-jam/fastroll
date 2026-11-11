//! Accumulate state transition integration tests
#![allow(unused_imports)]
use async_trait::async_trait;
use fr_asn_types::{
    accumulate::*,
    common::{AsnOpaqueHash, AsnServiceInfo},
    preimages::{
        AsnLookupMetaMapEntry, AsnLookupMetaMapKey, AsnPreimagesMapEntry, LookupMetaMapEntry,
        PreimagesMapEntry,
    },
};
use fr_block::{header_db::BlockHeaderDB, types::block::BlockHeader};
use fr_common::{workloads::WorkReport, Hash32, LookupsKey, Octets, ServiceId};
use fr_pvm_invocation::accumulate::utils::collect_accumulatable_reports;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{
        privileges::PrivilegedServices, AccountLookupsEntry, AccountLookupsEntryTimeslots,
        AccountMetadata, AccumulateHistory, AccumulateQueue, AuthQueue, EpochEntropy,
        LastAccumulateOutputs, Timeslot,
    },
};
use fr_test_utils::{
    generate_typed_tests,
    stf_harness::{run_test_case, StateTransitionTest},
};
use fr_transition::{
    error::TransitionError,
    state::{
        accumulate::{transition_accumulate_history, transition_accumulate_queue},
        history::transition_last_accumulate_outputs,
        services::{transition_on_accumulate, transition_services_last_accumulate_at},
        timeslot::transition_timeslot,
    },
};
use futures::future::join_all;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[allow(dead_code)]
struct AccumulateTest;

#[async_trait]
impl StateTransitionTest for AccumulateTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/accumulate";

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
        // Convert ASN pre-state into FastRoll types.
        let pre_timeslot = Timeslot::new(test_pre_state.slot);
        let pre_entropy = EpochEntropy([
            test_pre_state.entropy.clone(),
            Hash32::default(),
            Hash32::default(),
            Hash32::default(),
        ]);
        let pre_acc_queue = AccumulateQueue::from(test_pre_state.ready_queue.clone());
        let pre_acc_history = AccumulateHistory::from(test_pre_state.accumulated.clone());
        let pre_privileged_services = PrivilegedServices::from(test_pre_state.privileges.clone());

        // Load pre-state info the state cache.
        state_manager.add_timeslot(pre_timeslot).await?;
        state_manager.add_epoch_entropy(pre_entropy).await?;
        state_manager.add_accumulate_queue(pre_acc_queue).await?;
        state_manager
            .add_accumulate_history(pre_acc_history)
            .await?;

        // Load AuthQueue (required for partial state initialization)
        state_manager.add_auth_queue(AuthQueue::default()).await?;

        // Add regular accounts
        let regular_account_ids = test_pre_state
            .accounts
            .iter()
            .map(|a| a.id)
            .collect::<HashSet<_>>();
        for account in &test_pre_state.accounts {
            // Add service info
            state_manager
                .add_account_metadata(
                    account.id,
                    AccountMetadata::from(account.data.service.clone()),
                )
                .await?;
            // Add storage entries
            for storage_entry in &account.data.storage {
                let key = Octets::from_vec(storage_entry.key.0.clone());
                let val = StorageMapEntry::from(storage_entry.clone()).data;
                state_manager
                    .add_account_storage_entry(account.id, &key, val)
                    .await?
            }
            let mut preimage_size_map = HashMap::new(); // Required to construct `LookupsKey`

            // Add preimages entries
            for preimage in &account.data.preimage_blobs {
                let key = preimage.hash.clone();
                let val = PreimagesMapEntry::from(preimage.clone()).data;
                preimage_size_map.insert(key.clone(), preimage.blob.len());
                state_manager
                    .add_account_preimages_entry(account.id, &key, val)
                    .await?;
            }
            // Add lookups entries
            for lookup in &account.data.preimage_requests {
                let size = preimage_size_map
                    .get(&lookup.key.hash)
                    .expect("Preimage blob not provided");
                let key: LookupsKey = (lookup.key.hash.clone(), *size as u32);
                let val = AccountLookupsEntry {
                    value: AccountLookupsEntryTimeslots::try_from(
                        lookup
                            .value
                            .iter()
                            .map(|slot| Timeslot::new(*slot))
                            .collect::<Vec<_>>(),
                    )
                    .expect("Failed to convert between timeslot vec types"),
                };
                state_manager
                    .add_account_lookups_entry(account.id, key, val)
                    .await?;
            }
        }

        // Add service info for privileged services
        let mut privileged_service_ids = HashSet::new();
        privileged_service_ids.insert(pre_privileged_services.manager_service);
        for assign_service in &pre_privileged_services.assign_services {
            privileged_service_ids.insert(*assign_service);
        }
        privileged_service_ids.insert(pre_privileged_services.designate_service);
        for privileged_service_id in privileged_service_ids {
            if !regular_account_ids.contains(&privileged_service_id) {
                state_manager
                    .add_account_metadata(privileged_service_id, AccountMetadata::default())
                    .await?;
            }
        }
        state_manager
            .add_privileged_services(pre_privileged_services)
            .await?;

        // Add LastAccumulateOutputs (default value)
        state_manager
            .add_last_accumulate_outputs(LastAccumulateOutputs::default())
            .await?;

        Ok(())
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
        // Convert ASN Input into FastRoll types.
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
        _header_db: Arc<BlockHeaderDB>,
        _new_header: &mut BlockHeader,
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
            curr_timeslot,
        );
        let acc_summary =
            transition_on_accumulate(state_manager.clone(), &accumulatable_reports).await?;
        transition_last_accumulate_outputs(state_manager.clone(), acc_summary.output_pairs).await?;
        let accumulated_services: Vec<ServiceId> =
            acc_summary.accumulate_stats.keys().cloned().collect();
        transition_services_last_accumulate_at(state_manager.clone(), &accumulated_services)
            .await?;
        transition_accumulate_history(
            state_manager.clone(),
            &accumulatable_reports,
            acc_summary.accumulated_reports_count,
        )
        .await?;
        transition_accumulate_queue(
            state_manager.clone(),
            &queued_reports,
            pre_timeslot,
            curr_timeslot,
        )
        .await?;
        let last_accumulate_outputs = state_manager.get_last_accumulate_outputs().await?;

        Ok(JamTransitionOutput {
            accumulate_root: last_accumulate_outputs.accumulate_root()?,
        })
    }

    fn map_error_code(_e: TransitionError) -> Self::ErrorCode {
        // Not specifying the exact error type for now
        AccumulateErrorCode::reserved
    }

    fn extract_output(
        _new_header: &BlockHeader,
        transition_output: Option<&Self::JamTransitionOutput>,
        error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output {
        if error_code.is_some() {
            return Output::err;
        }

        Output::ok(AsnOpaqueHash::from(
            transition_output.unwrap().accumulate_root.clone(),
        ))
    }

    async fn extract_post_state(
        state_manager: Arc<StateManager>,
        pre_state: &Self::State,
        test_case_post_state: &Self::State,
        error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError> {
        if error_code.is_some() {
            // Rollback state transition
            return Ok(pre_state.clone());
        }

        // Get the posterior state from the state cache.
        let curr_timeslot = state_manager.get_timeslot().await?;
        let epoch_entropy = state_manager.get_epoch_entropy().await?;
        let curr_entropy = epoch_entropy.current();
        let curr_acc_queue = state_manager.get_accumulate_queue().await?;
        let curr_acc_history = state_manager.get_accumulate_history().await?;
        let curr_privileged_services = state_manager.get_privileged_services().await?;
        // Iterate on post state accounts from the test case so that we can get the full list of
        // account storage/preimages items.
        let curr_accounts = join_all(test_case_post_state.accounts.iter().map(|s| async {
            let curr_metadata = AsnServiceInfo::from(
                state_manager
                    .get_account_metadata(s.id)
                    .await
                    .unwrap()
                    .unwrap(),
            );

            let curr_storage_entries = join_all(s.data.storage.iter().map(|e| async {
                // Get the key from the post-state
                let key = Octets::from_vec(e.key.0.clone());
                // Get the posterior storage value
                let storage_entry = state_manager
                    .get_account_storage_entry(s.id, &key)
                    .await
                    .unwrap()
                    .unwrap();
                AsnStorageMapEntry::from(StorageMapEntry {
                    key,
                    data: storage_entry,
                })
            }))
            .await;
            let curr_preimages = join_all(s.data.preimage_blobs.iter().map(|e| async {
                // Get the key from the post-state
                let key = e.hash.clone();
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
            let curr_lookups = join_all(s.data.preimage_blobs.iter().map(|e| async {
                // Get the key from the post-state
                let key: LookupsKey = (e.hash.clone(), e.blob.len() as u32);
                // Get the posterior lookups value
                let lookups = state_manager
                    .get_account_lookups_entry(s.id, &key)
                    .await
                    .unwrap()
                    .unwrap();
                AsnLookupMetaMapEntry {
                    key: AsnLookupMetaMapKey {
                        hash: key.0,
                        length: key.1,
                    },
                    value: lookups
                        .value
                        .into_iter()
                        .map(|timeslot| timeslot.slot())
                        .collect(),
                }
            }))
            .await;

            AsnAccountsMapEntry {
                id: s.id,
                data: AsnAccount {
                    service: curr_metadata,
                    storage: curr_storage_entries,
                    preimage_blobs: curr_preimages,
                    preimage_requests: curr_lookups,
                },
            }
        }))
        .await;

        Ok(State {
            slot: curr_timeslot.slot(),
            entropy: curr_entropy.clone(),
            ready_queue: curr_acc_queue.into(),
            accumulated: curr_acc_history.into(),
            privileges: curr_privileged_services.into(),
            accounts: curr_accounts,
        })
    }

    fn assert_post_state(post_state: Self::State, test_case_post_state: Self::State) {
        assert_eq!(post_state.slot, test_case_post_state.slot);
        assert_eq!(post_state.entropy, test_case_post_state.entropy);
        assert_eq!(post_state.ready_queue, test_case_post_state.ready_queue);
        assert_eq!(post_state.accumulated, test_case_post_state.accumulated);
        assert_eq!(post_state.privileges, test_case_post_state.privileges);
        for (actual, expected) in post_state
            .accounts
            .into_iter()
            .zip(test_case_post_state.accounts)
        {
            assert_eq!(actual.id, expected.id);
            assert_eq!(actual.data.service, expected.data.service);
            assert_eq!(actual.data.storage.len(), expected.data.storage.len());
            for (actual_storage, expected_storage) in
                actual.data.storage.into_iter().zip(expected.data.storage)
            {
                assert_eq!(actual_storage.key, expected_storage.key);
                assert_eq!(actual_storage.value, expected_storage.value);
            }
            assert_eq!(
                actual.data.preimage_blobs.len(),
                expected.data.preimage_blobs.len()
            );
            for (actual_preimages, expected_preimages) in actual
                .data
                .preimage_blobs
                .into_iter()
                .zip(expected.data.preimage_blobs)
            {
                assert_eq!(actual_preimages.hash, expected_preimages.hash);
                assert_eq!(actual_preimages.blob, expected_preimages.blob);
            }
        }
    }
}

generate_typed_tests! {
    AccumulateTest,

    // No reports.
    no_available_reports_1: "no_available_reports-1.json",

    // Report with no dependencies.
    #[ignore = "GP 0.8.0 not implemented"]
    process_one_immediate_report_1: "process_one_immediate_report-1.json",

    // Report with unsatisfied dependency added to the ready-queue.
    enqueue_and_unlock_simple_1: "enqueue_and_unlock_simple-1.json",

    // Report with no dependencies that resolves previous dependency.
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_simple_2: "enqueue_and_unlock_simple-2.json",

    // Report with unsatisfied segment tree root dependency added to the ready-queue.
    enqueue_and_unlock_with_sr_lookup_1: "enqueue_and_unlock_with_sr_lookup-1.json",

    // Report with no dependencies that resolves previous dependency.
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_with_sr_lookup_2: "enqueue_and_unlock_with_sr_lookup-2.json",

    // Two reports with unsatisfied dependencies added to the ready-queue.
    enqueue_and_unlock_chain_1: "enqueue_and_unlock_chain-1.json",

    // Two additional reports with unsatisfied dependencies added to the ready-queue.
    enqueue_and_unlock_chain_2: "enqueue_and_unlock_chain-2.json",

    // Two additional reports. One with unsatisfied dependencies, thus added to the ready-queue.
    // One report is accumulated and resolves two previously enqueued reports.
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_chain_3: "enqueue_and_unlock_chain-3.json",

    // Report that resolves all remaining queued dependencies.
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_chain_4: "enqueue_and_unlock_chain-4.json",

    // Two reports with unsatisfied dependencies added to the ready-queue.
    enqueue_and_unlock_chain_wraps_1: "enqueue_and_unlock_chain_wraps-1.json",

    // Two additional reports, one with no dependencies and thus immediately accumulated.
    // The other is pushed to the ready-queue which fills up the wraps around
    // (ready-queue is a ring buffer).
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_chain_wraps_2: "enqueue_and_unlock_chain_wraps-2.json",

    // Two additional reports with unsatisfied dependencies pushed to the ready-queue.
    enqueue_and_unlock_chain_wraps_3: "enqueue_and_unlock_chain_wraps-3.json",

    // Two additional reports, one with no dependencies and thus immediately accumulated.
    // Three old entries in the ready-queue are removed.
    #[ignore = "GP 0.8.0 not implemented"]
    enqueue_and_unlock_chain_wraps_4: "enqueue_and_unlock_chain_wraps-4.json",

    // Report with no dependencies resolves all previous enqueued reports.
    #[ignore = "GP 0.8.0 not implemented"]
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
    #[ignore = "GP 0.8.0 not implemented"]
    accumulate_ready_queued_reports_1: "accumulate_ready_queued_reports-1.json",

    // Check that ready-queue and accumulated-reports queues are shifted.
    // A new available report is supplied.
    #[ignore = "GP 0.8.0 not implemented"]
    queues_are_shifted_1: "queues_are_shifted-1.json",

    // Check that ready-queue and accumulated-reports queues are shifted.
    // No new report is supplied.
    queues_are_shifted_2: "queues_are_shifted-2.json",

    // Two reports with unsatisfied dependencies added to the ready-queue.
    ready_queue_editing_1: "ready_queue_editing-1.json",

    // Two reports, one with unsatisfied dependency added to the ready-queue.
    // One accumulated. Ready queue items dependencies are edited.
    #[ignore = "GP 0.8.0 not implemented"]
    ready_queue_editing_2: "ready_queue_editing-2.json",

    // One report unlocks reports in the ready-queue.
    #[ignore = "GP 0.8.0 not implemented"]
    ready_queue_editing_3: "ready_queue_editing-3.json",

    #[ignore = "GP 0.8.0 not implemented"]
    same_code_different_services_1: "same_code_different_services-1.json",

    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_ejected_service_1: "transfer_for_ejected_service-1.json",

    work_for_ejected_service_1: "work_for_ejected_service-1.json",

    #[ignore = "GP 0.8.0 not implemented"]
    work_for_ejected_service_2: "work_for_ejected_service-2.json",

    #[ignore = "GP 0.8.0 not implemented"]
    work_for_ejected_service_3: "work_for_ejected_service-3.json",

    // A transfer is made to a live service.
    // The deferred transfer is delivered to its accumulate in the following round.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_live_service_1: "transfer_for_live_service-1.json",

    // A service ejects a zombie service which has a work digest in the same round.
    // The ejector id is lower than the zombie id. The statistics of the zombie count the digest.
    #[ignore = "GP 0.8.0 not implemented"]
    work_for_service_ejected_in_same_round_low_ejector_1: "work_for_service_ejected_in_same_round_low_ejector-1.json",

    // Same as above, with an ejector id higher than the zombie id.
    #[ignore = "GP 0.8.0 not implemented"]
    work_for_service_ejected_in_same_round_high_ejector_1: "work_for_service_ejected_in_same_round_high_ejector-1.json",

    // A service ejects a zombie service in the round in which a transfer to the zombie arrives.
    // The ejector id is lower than the zombie id. The statistics of the zombie count the transfer.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_service_ejected_in_same_round_low_ejector_1: "transfer_for_service_ejected_in_same_round_low_ejector-1.json",

    // Same as above, with an ejector id higher than the zombie id.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_service_ejected_in_same_round_high_ejector_1: "transfer_for_service_ejected_in_same_round_high_ejector-1.json",

    // A service sends a transfer to a zombie service which accumulates and is ejected in the same round.
    // The transfer arrives in the next round, when the zombie no longer exists, and its amount is burned.
    // The ejector id is lower than the zombie id. The statistics of the zombie count the work digest and the transfer.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_ejected_service_that_accumulates_low_ejector_1: "transfer_for_ejected_service_that_accumulates_low_ejector-1.json",

    // Same as above, with an ejector id higher than the zombie id.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_for_ejected_service_that_accumulates_high_ejector_1: "transfer_for_ejected_service_that_accumulates_high_ejector-1.json",

    // One invocation calls `transfer` to a zombie service and then `eject` on it.
    // Both succeed. The amount is burned in the next round.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_to_service_ejected_by_sender_transfer_first_1: "transfer_to_service_ejected_by_sender_transfer_first-1.json",

    // One invocation calls `eject` on a zombie service and then `transfer` to it.
    // The `transfer` returns `WHO`. Nothing is burned.
    #[ignore = "GP 0.8.0 not implemented"]
    transfer_to_service_ejected_by_sender_eject_first_1: "transfer_to_service_ejected_by_sender_eject_first-1.json",

    // The registrar ejects a zombie service and creates its id again with `new`, in one invocation.
    // Both host calls succeed. The prior account stays and gets the endowment.
    // The new account does not reach the state (GP 0.8.0 merge rule).
    #[ignore = "GP 0.8.0 not implemented"]
    recreate_ejected_service_1: "recreate_ejected_service-1.json",

    // Same as `recreate_ejected_service-1`, but the zombie accumulates a transfer in the same round.
    // The prior account stays and gets the transfer and the endowment.
    #[ignore = "GP 0.8.0 not implemented"]
    recreate_ejected_service_that_accumulates_1: "recreate_ejected_service_that_accumulates-1.json",

    // Same as `recreate_ejected_service_that_accumulates-1`, but the registrar id is higher than the zombie id.
    // The own result of the zombie merges first. The prior account stays and gets the transfer and the endowment.
    #[ignore = "GP 0.8.0 not implemented"]
    recreate_ejected_service_by_higher_registrar_1: "recreate_ejected_service_by_higher_registrar-1.json",

    // The registrar ejects a zombie service which has a work digest in the same round.
    // In a later round of the same block the registrar creates the id again. The endowment transfer fails.
    // The new account gets the slot of the block as its last accumulation slot.
    #[ignore = "GP 0.8.0 not implemented"]
    recreate_service_ejected_in_earlier_round_1: "recreate_service_ejected_in_earlier_round-1.json",

    // `designate` host call with one key less than the minimum validators set size.
    #[ignore = "GP 0.8.0 not implemented"]
    designate_with_invalid_count_1: "designate_with_invalid_count-1.json",

    // `designate` host call with the minimum validators set size.
    #[ignore = "GP 0.8.0 not implemented"]
    designate_with_invalid_count_2: "designate_with_invalid_count-2.json",

    // `solicit` host call with a preimage length of 2^32. Rejected.
    #[ignore = "GP 0.8.0 not implemented"]
    preimage_len_bound_1: "preimage_len_bound-1.json",

    // `solicit` host call with a preimage length of 2^32-1. Accepted.
    #[ignore = "GP 0.8.0 not implemented"]
    preimage_len_bound_2: "preimage_len_bound-2.json",

    // `forget` host call for the unprovided preimage of length 2^32-1. Dropped.
    #[ignore = "GP 0.8.0 not implemented"]
    preimage_len_bound_3: "preimage_len_bound-3.json",

    // Service in the always-accumulate set, no reports.
    // Accumulates zero items within its free gas.
    always_accumulate_1: "always_accumulate-1.json",

    // Same service with one report.
    // The item and the free gas are accumulated together.
    #[ignore = "GP 0.8.0 not implemented"]
    always_accumulate_2: "always_accumulate-2.json",

    // `assign` host call from a service which is not the assigner of the core. Rejected.
    #[ignore = "GP 0.8.0 not implemented"]
    assign_from_non_assigner_1: "assign_from_non_assigner-1.json",

    // `assign` host call for a core index out of range. Rejected.
    #[ignore = "GP 0.8.0 not implemented"]
    assign_from_non_assigner_2: "assign_from_non_assigner-2.json",

    // `assign` host call from the assigner, which hands the core over to another service.
    #[ignore = "GP 0.8.0 not implemented"]
    assign_from_non_assigner_3: "assign_from_non_assigner-3.json",

    // `bless` host call from the designator, which is not the manager.
    // The vector accepts it and hands the designate role over to another service.
    #[ignore = "GP deviation, bless from a non-manager is accepted where GP 0.8.0 returns HUH (GP #519)"]
    bless_from_non_manager_1: "bless_from_non_manager-1.json",

    // The manager and the designator both change the designator in the same round.
    // The manager choice wins.
    #[ignore = "GP deviation, bless from a non-manager is accepted where GP 0.8.0 returns HUH (GP #519)"]
    bless_from_non_manager_2: "bless_from_non_manager-2.json",

    // `upgrade` host call. Code hash and minimum gas requirements are replaced.
    #[ignore = "GP 0.8.0 not implemented"]
    upgrade_service_1: "upgrade_service-1.json",

    // `lookup` host call for an unknown preimage. Nothing is returned.
    #[ignore = "GP 0.8.0 not implemented"]
    lookup_foreign_preimage_1: "lookup_foreign_preimage-1.json",

    // `lookup` host call for a preimage held by another service.
    #[ignore = "GP 0.8.0 not implemented"]
    lookup_foreign_preimage_2: "lookup_foreign_preimage-2.json",

    // `provide` host call for a service which did not request the preimage. Rejected.
    #[ignore = "GP 0.8.0 not implemented"]
    provide_preimage_1: "provide_preimage-1.json",

    // `provide` host call for a requested preimage. The preimage becomes available.
    #[ignore = "GP 0.8.0 not implemented"]
    provide_preimage_2: "provide_preimage-2.json",

    // `new` host call from the registrar with a requested id.
    // The endowment is delivered as a deferred transfer to the new service, whose code is not available.
    #[ignore = "GP 0.8.0 not implemented"]
    create_service_1: "create_service-1.json",

    // Two services accumulated in the same round.
    // The first writes a storage key, the second reads that key with a foreign `read` host call.
    // The read doesn't observe the write made in the same round.
    #[ignore = "GP 0.8.0 not implemented"]
    same_round_storage_isolation_1: "same_round_storage_isolation-1.json",

    // Same foreign `read` in the next block. The committed value is observed.
    #[ignore = "GP 0.8.0 not implemented"]
    same_round_storage_isolation_2: "same_round_storage_isolation-2.json",
}
