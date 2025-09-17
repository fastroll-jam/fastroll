use crate::{error::TransitionError, state::privileges};
use fr_block::types::extrinsics::preimages::PreimagesXt;
use fr_common::{
    workloads::work_report::WorkReport, ServiceId, StateKey, UnsignedGas,
    ACCUMULATION_GAS_ALL_CORES, ACCUMULATION_GAS_PER_CORE, CORE_COUNT,
};
use fr_crypto::{hash, Blake2b256};
use fr_extrinsics::validation::preimages::PreimagesXtValidator;
use fr_pvm_invocation::{
    accumulate::{pipeline::accumulate_outer, utils::select_deferred_transfers},
    on_transfer::OnTransferInvocation,
    prelude::{AccountSandbox, SandboxEntryAccessor, SandboxEntryStatus},
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
    state_utils::{
        get_account_lookups_state_key, get_account_metadata_state_key,
        get_account_preimage_state_key, get_account_storage_state_key,
    },
    types::AccountPreimagesEntry,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Collection of all added or removed account-specific state keys of all service accounts.
///
/// Note: This is utility struct for fuzz testing to track all post-importing state entries,
/// NOT part of the Graypaper spec.
#[derive(Clone, Default)]
pub struct AccountStateChanges {
    pub inner: HashMap<ServiceId, AccountStateChange>,
}

impl AccountStateChanges {
    pub fn extend(&mut self, changes: AccountStateChanges) {
        for (service_id, change) in changes.inner.into_iter() {
            self.inner
                .entry(service_id)
                .and_modify(|e| e.extend(change.clone()))
                .or_insert(change);
        }
    }
}

/// Collection of all added or removed account-specific state keys of a specific service account.
#[derive(Clone, Default)]
pub struct AccountStateChange {
    pub added_state_keys: HashSet<StateKey>,
    pub removed_state_keys: HashSet<StateKey>,
}

impl AccountStateChange {
    pub fn extend(&mut self, change: AccountStateChange) {
        self.added_state_keys.extend(change.added_state_keys);
        self.removed_state_keys.extend(change.removed_state_keys);
    }
}

pub struct AccumulateSummary {
    pub accumulated_reports_count: usize,
    pub deferred_transfers: Vec<DeferredTransfer>,
    pub output_pairs: AccumulationOutputPairs,
    pub accumulate_stats: AccumulateStats,
    /// A utility field to keep track of changeset of state keys after state transitions (for fuzzing).
    pub account_state_changes: AccountStateChanges,
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
/// - `host_assign`
///
/// ### Staging Set
/// - `host_designate`
///
/// ### Auth Queue
/// - `host_assign`
pub async fn transition_on_accumulate(
    state_manager: Arc<StateManager>,
    reports: &[WorkReport], // R^*
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
    .map_err(TransitionError::PVMInvokeError)?;

    // Collect account state change set of all services
    let mut account_state_changes = AccountStateChanges::default();

    // Transition service accounts
    for (&service_id, sandbox) in outer_accumulate_result
        .partial_state_union
        .accounts_sandbox
        .iter_mut()
    {
        let account_state_change =
            transition_service_account(state_manager.clone(), service_id, sandbox).await?;
        account_state_changes
            .inner
            .insert(service_id, account_state_change);
    }

    privileges::run_privileged_transitions(
        state_manager,
        outer_accumulate_result.partial_state_union,
    )
    .await?;

    Ok(AccumulateSummary {
        accumulated_reports_count: outer_accumulate_result.accumulated_reports_count,
        deferred_transfers: outer_accumulate_result.deferred_transfers,
        output_pairs: outer_accumulate_result.service_output_pairs,
        accumulate_stats: AccumulateStats::from_accumulated_reports(
            &reports[..outer_accumulate_result.accumulated_reports_count],
            &outer_accumulate_result.service_gas_pairs,
        ),
        account_state_changes,
    })
}

async fn transition_service_account(
    state_manager: Arc<StateManager>,
    service_id: ServiceId,
    sandbox: &mut AccountSandbox<StateManager>,
) -> Result<AccountStateChange, TransitionError> {
    // Collect account state change set of the given service
    let mut account_state_change = AccountStateChange::default();

    match &sandbox.metadata.status() {
        SandboxEntryStatus::Added => {
            state_manager
                .add_account_metadata(
                    service_id,
                    sandbox.metadata.get_cloned().expect("Should exist"),
                )
                .await?;
            account_state_change
                .added_state_keys
                .insert(get_account_metadata_state_key(service_id));
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
            account_state_change
                .removed_state_keys
                .insert(get_account_metadata_state_key(service_id));
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
                account_state_change
                    .added_state_keys
                    .insert(get_account_storage_state_key(service_id, k));
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
                    .await?;
                account_state_change
                    .removed_state_keys
                    .insert(get_account_storage_state_key(service_id, k));
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
                account_state_change
                    .added_state_keys
                    .insert(get_account_preimage_state_key(service_id, k));
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
                    .await?;
                account_state_change
                    .removed_state_keys
                    .insert(get_account_preimage_state_key(service_id, k));
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
                account_state_change
                    .added_state_keys
                    .insert(get_account_lookups_state_key(service_id, k));
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
                    .await?;
                account_state_change
                    .removed_state_keys
                    .insert(get_account_lookups_state_key(service_id, k));
            }
            _ => (),
        }
    }

    Ok(account_state_change)
}

pub struct OnTransferSummary {
    pub stats: OnTransferStats,
    /// A utility field to keep track of changeset of state keys after state transitions (for fuzzing).
    pub account_state_changes: AccountStateChanges,
}

/// The second state transition function of service accounts, updating `last_accumulate_at` field of
/// all service accounts that had been accumulated during `transition_on_accumulate`, yielding `δ‡`.
pub async fn transition_services_last_accumulate_at(
    state_manager: Arc<StateManager>,
    accumulated_services: &[ServiceId],
) -> Result<(), TransitionError> {
    // Mark the last accumulate timeslots of all accumulated services in the blocks.
    let curr_timeslot_index = state_manager.get_timeslot().await?.slot();
    for service_id in accumulated_services {
        // Directly mutate account metadata
        // Note: not considering new accounts having accumulated items within the same block
        // of the creation. `StateMut` variant is always `Update` here.
        state_manager
            .with_mut_account_metadata(
                StateMut::Update,
                *service_id,
                |metadata| -> Result<(), StateManagerError> {
                    metadata.last_accumulate_at = curr_timeslot_index;
                    Ok(())
                },
            )
            .await?
    }

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
) -> Result<OnTransferSummary, TransitionError> {
    // Gather all unique destination addresses.
    let destinations: HashSet<ServiceId> = transfers.iter().map(|t| t.to).collect();
    let mut stats = OnTransferStats::default();

    // Collect account state change set of all services
    let mut account_state_changes = AccountStateChanges::default();

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
            let account_state_change =
                transition_service_account(state_manager.clone(), destination, recipient_sandbox)
                    .await?;
            account_state_changes
                .inner
                .insert(destination, account_state_change);
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

    Ok(OnTransferSummary {
        stats,
        account_state_changes,
    })
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
