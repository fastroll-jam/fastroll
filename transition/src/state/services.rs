use crate::error::TransitionError;
use fr_block::types::extrinsics::preimages::PreimagesXt;
use fr_common::{
    workloads::work_report::WorkReport, ServiceId, UnsignedGas, ACCUMULATION_GAS_ALL_CORES,
    ACCUMULATION_GAS_PER_CORE, CORE_COUNT,
};
use fr_crypto::{hash, Blake2b256};
use fr_extrinsics::validation::preimages::PreimagesXtValidator;
use fr_pvm_invocation::{
    entrypoints::on_transfer::OnTransferInvocation,
    pipeline::{accumulate_outer, utils::select_deferred_transfers},
    prelude::{AccountSandbox, AccumulatePartialState, SandboxEntryAccessor, SandboxEntryStatus},
};
use fr_pvm_types::{
    invoke_args::{DeferredTransfer, OnTransferInvokeArgs},
    invoke_results::AccumulationOutputPairs,
    stats::{AccumulateStats, OnTransferStats, OnTransferStatsEntry},
};
use fr_state::{
    cache::StateMut,
    error::StateManagerError,
    manager::StateManager,
    types::{AccountFootprintDelta, AccountPreimagesEntry},
};
use std::{collections::HashSet, sync::Arc};

pub struct AccumulateSummary {
    pub accumulated_reports_count: usize,
    pub deferred_transfers: Vec<DeferredTransfer>,
    pub output_pairs: AccumulationOutputPairs,
    pub accumulate_stats: AccumulateStats,
}

/// Processes state transitions of service accounts, `PrivilegedServices`, `StagingSet`
/// and `AuthQueue` by invoking the `accumulate` PVM entrypoint.
///
/// # Transitions
///
/// This handles the first state transition for service accounts, yielding `δ†`.
/// Also, it handles privileged service transitions, yielding `χ′`, `ι′` and `φ′`.
///
/// The following state components are copied into `AccumulatePartialState` and then mutated
/// during the `accumulate` by host functions. After the execution of the `accumulate`,
/// the mutations in `AccumulatePartialState` are copied back into the `StateManager`.
///
/// ### Service Accounts
/// - `host_write`
/// - `host_new`
/// - `host_upgrade`
/// - `host_transfer`
/// - `host_eject`
/// - `host_solicit`
/// - `host_forget`
///
/// ### Privileged Services
/// - `host_bless`
///
/// ### Staging Set
/// - `host_designate`
///
/// ### Auth Queue
/// - `host_assign`
pub async fn transition_on_accumulate(
    state_manager: Arc<StateManager>,
    reports: &[WorkReport], // W^*
) -> Result<AccumulateSummary, TransitionError> {
    tracing::info!("Accumulating {} reports", reports.len());
    let always_accumulate_services = &state_manager
        .get_privileged_services()
        .await?
        .always_accumulate_services;

    let gas_limit = ACCUMULATION_GAS_ALL_CORES.max(
        ACCUMULATION_GAS_PER_CORE * CORE_COUNT as UnsignedGas
            + always_accumulate_services.values().sum::<UnsignedGas>(),
    );

    let mut outer_accumulate_result = accumulate_outer(
        state_manager.clone(),
        gas_limit,
        reports,
        always_accumulate_services,
    )
    .await
    .map_err(TransitionError::PVMError)?;

    // Transition service accounts
    for (&service_id, sandbox) in outer_accumulate_result
        .partial_state_union
        .accounts_sandbox
        .iter_mut()
    {
        transition_service_account(state_manager.clone(), service_id, sandbox).await?;
    }

    run_privileged_transitions(state_manager, outer_accumulate_result.partial_state_union).await?;

    Ok(AccumulateSummary {
        accumulated_reports_count: outer_accumulate_result.accumulated_reports_count,
        deferred_transfers: outer_accumulate_result.deferred_transfers,
        output_pairs: outer_accumulate_result.service_output_pairs,
        accumulate_stats: AccumulateStats::from_accumulated_reports(
            &reports[..outer_accumulate_result.accumulated_reports_count],
            &outer_accumulate_result.service_gas_pairs,
        ),
    })
}

async fn transition_service_account(
    state_manager: Arc<StateManager>,
    service_id: ServiceId,
    sandbox: &mut AccountSandbox,
) -> Result<(), TransitionError> {
    // TODO: Optimize writes

    // Iterate all storage entries of the account sandbox and update storage footprint fields
    // of the `AccountMetadata` if there is any change.
    let storage_usage_delta = sandbox.storage_usage_delta_aggregated();
    if let Some(metadata_mut) = sandbox.metadata.as_mut() {
        let updated =
            metadata_mut.update_footprints(AccountFootprintDelta::from(storage_usage_delta));
        if updated {
            sandbox.metadata.mark_updated()
        }
    }

    match &sandbox.metadata.status() {
        SandboxEntryStatus::Added => {
            state_manager
                .add_account_metadata(
                    service_id,
                    sandbox.metadata.get_cloned().expect("Should exist"),
                )
                .await?;
        }
        SandboxEntryStatus::Updated => {
            state_manager
                .with_mut_account_metadata(
                    StateMut::Update,
                    service_id,
                    |metadata| -> Result<(), StateManagerError> {
                        *metadata = sandbox.metadata.get_cloned().expect("Should exist");
                        Ok(())
                    },
                )
                .await?;
        }
        SandboxEntryStatus::Removed => {
            state_manager
                .with_mut_account_metadata(
                    StateMut::Remove,
                    service_id,
                    |_| -> Result<(), StateManagerError> { Ok(()) },
                )
                .await?;
        }
        _ => (),
    }

    for (k, v) in sandbox.storage.iter() {
        match v.status() {
            SandboxEntryStatus::Added => {
                state_manager
                    .add_account_storage_entry(
                        service_id,
                        k,
                        v.get_cloned().expect("Should exist").into_entry(),
                    )
                    .await?;
            }
            SandboxEntryStatus::Updated => {
                state_manager
                    .with_mut_account_storage_entry(
                        StateMut::Update,
                        service_id,
                        k,
                        |entry| -> Result<(), StateManagerError> {
                            *entry = v.get_cloned().expect("Should exist").into_entry();
                            Ok(())
                        },
                    )
                    .await?;
            }
            SandboxEntryStatus::Removed => {
                state_manager
                    .with_mut_account_storage_entry(
                        StateMut::Remove,
                        service_id,
                        k,
                        |_| -> Result<(), StateManagerError> { Ok(()) },
                    )
                    .await?
            }
            _ => (),
        }
    }

    for (k, v) in sandbox.preimages.iter() {
        match v.status() {
            SandboxEntryStatus::Added => {
                state_manager
                    .add_account_preimages_entry(
                        service_id,
                        k,
                        v.get_cloned().expect("Should exist"),
                    )
                    .await?;
            }
            SandboxEntryStatus::Updated => {
                state_manager
                    .with_mut_account_preimages_entry(
                        StateMut::Update,
                        service_id,
                        k,
                        |entry| -> Result<(), StateManagerError> {
                            *entry = v.get_cloned().expect("Should exist");
                            Ok(())
                        },
                    )
                    .await?;
            }
            SandboxEntryStatus::Removed => {
                state_manager
                    .with_mut_account_preimages_entry(
                        StateMut::Remove,
                        service_id,
                        k,
                        |_| -> Result<(), StateManagerError> { Ok(()) },
                    )
                    .await?
            }
            _ => (),
        }
    }

    for (k, v) in sandbox.lookups.iter() {
        match v.status() {
            SandboxEntryStatus::Added => {
                state_manager
                    .add_account_lookups_entry(
                        service_id,
                        k.clone(),
                        v.get_cloned().expect("Should exist").into_entry(),
                    )
                    .await?;
            }
            SandboxEntryStatus::Updated => {
                state_manager
                    .with_mut_account_lookups_entry(
                        StateMut::Update,
                        service_id,
                        k.clone(),
                        |entry| -> Result<(), StateManagerError> {
                            *entry = v.get_cloned().expect("Should exist").into_entry();
                            Ok(())
                        },
                    )
                    .await?;
            }
            SandboxEntryStatus::Removed => {
                state_manager
                    .with_mut_account_lookups_entry(
                        StateMut::Remove,
                        service_id,
                        k.clone(),
                        |_| -> Result<(), StateManagerError> { Ok(()) },
                    )
                    .await?
            }
            _ => (),
        }
    }

    Ok(())
}

async fn run_privileged_transitions(
    state_manager: Arc<StateManager>,
    partial_state_union: AccumulatePartialState,
) -> Result<(), TransitionError> {
    // Transition staging set
    if let Some(new_staging_set) = partial_state_union.new_staging_set {
        state_manager
            .with_mut_staging_set(
                StateMut::Update,
                |staging_set| -> Result<(), StateManagerError> {
                    *staging_set = new_staging_set;
                    Ok(())
                },
            )
            .await?;
    }

    // Transition auth queue
    if let Some(new_auth_queue) = partial_state_union.new_auth_queue {
        state_manager
            .with_mut_auth_queue(
                StateMut::Update,
                |auth_queue| -> Result<(), StateManagerError> {
                    *auth_queue = new_auth_queue;
                    Ok(())
                },
            )
            .await?;
    }

    // Transition privileged services
    let manager_service_sandboxed = partial_state_union.manager_service;
    let assign_services_sandboxed = partial_state_union.assign_services;
    let designate_service_sandboxed = partial_state_union.designate_service;
    let always_accumulate_services_sandboxed = partial_state_union.always_accumulate_services;
    state_manager
        .with_mut_privileged_services(
            StateMut::Update,
            |privileges| -> Result<(), StateManagerError> {
                privileges.manager_service = manager_service_sandboxed;
                privileges.assign_services = assign_services_sandboxed;
                privileges.designate_service = designate_service_sandboxed;
                privileges.always_accumulate_services = always_accumulate_services_sandboxed;
                Ok(())
            },
        )
        .await?;

    Ok(())
}

/// State transition function of service accounts, processing deferred transfers.
///
/// # Transitions
///
/// This handles the second state transition for service accounts, invoking the `on_transfer`
/// PVM entrypoint and yielding `δ‡`.
///
/// Steps:
/// 1. Identifies unique destination addresses from the input transfers.
/// 2. For each destination, selects relevant transfers and invokes the PVM `on_transfer` entrypoint.
/// 3. Updates service account states based on the PVM invocation results.
pub async fn transition_services_on_transfer(
    state_manager: Arc<StateManager>,
    transfers: &[DeferredTransfer],
) -> Result<OnTransferStats, TransitionError> {
    // Gather all unique destination addresses.
    let destinations: HashSet<ServiceId> = transfers.iter().map(|t| t.to).collect();
    let mut stats = OnTransferStats::default();

    // Invoke PVM `on-transfer` entrypoint for each destination.
    for destination in destinations {
        let transfers = select_deferred_transfers(transfers, destination);
        let transfers_count = transfers.len();
        let mut on_transfer_result = OnTransferInvocation::on_transfer(
            state_manager.clone(),
            &OnTransferInvokeArgs {
                destination,
                transfers,
            },
        )
        .await?;

        if let Some(balance_change_set) = on_transfer_result.balance_change_set {
            state_manager
                .with_mut_account_metadata(
                    StateMut::Update,
                    balance_change_set.recipient,
                    |metadata| -> Result<(), StateManagerError> {
                        metadata.add_balance(balance_change_set.added_amount);
                        Ok(())
                    },
                )
                .await?;
        }

        if let Some(ref mut recipient_sandbox) = on_transfer_result.recipient_sandbox {
            transition_service_account(state_manager.clone(), destination, recipient_sandbox)
                .await?
        }

        if transfers_count != 0 {
            stats.insert(
                destination,
                OnTransferStatsEntry {
                    transfers_count: transfers_count as u32,
                    gas_used: on_transfer_result.gas_used,
                },
            );
        }
    }

    Ok(stats)
}

/// State transition function of service accounts, integrating provided `PreimagesXt` data into
/// preimage storages. Preimages must be solicited by services but not yet provided.
///
/// # Transitions
///
/// This handles the final state transition for service accounts, yielding `δ′`.
/// Once entries in `PreimagesXt` are validated, preimage octets are integrated into the
/// preimages storages of relevant service accounts and current timeslot is pushed into the
/// lookups storages to mark the preimage data being available.
pub async fn transition_services_integrate_preimages(
    state_manager: Arc<StateManager>,
    preimages_xt: &PreimagesXt,
) -> Result<(), TransitionError> {
    // TODO: check if this should be explicitly validated against the prior service accounts `δ` as well.
    // Validate preimages extrinsic data.
    let preimages_validator = PreimagesXtValidator::new(state_manager.clone());
    preimages_validator.validate(preimages_xt).await?;

    let curr_timeslot = state_manager.get_timeslot().await?;

    for xt in preimages_xt.iter() {
        let preimage_data_hash = hash::<Blake2b256>(&xt.preimage_data)?;

        // Add the preimage data entry
        state_manager
            .add_account_preimages_entry(
                xt.service_id,
                &preimage_data_hash,
                AccountPreimagesEntry::new(xt.preimage_data.clone()),
            )
            .await?;

        // Push current timeslot value to the lookup map
        let preimage_data_len = xt.preimage_data_len();
        let lookups_key = (preimage_data_hash, preimage_data_len as u32);
        state_manager
            .with_mut_account_lookups_entry(StateMut::Update, xt.service_id, lookups_key, |entry| -> Result<(), StateManagerError> {
                entry.value.try_push(curr_timeslot).expect(
                    "Lookups metadata storage should have an empty timeslot sequence entry to integrate preimages.",
                );
                Ok(())
            })
            .await?
    }

    Ok(())
}
