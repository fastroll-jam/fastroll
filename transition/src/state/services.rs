use crate::error::TransitionError;
use rjam_common::{
    ServiceId, UnsignedGas, ACCUMULATION_GAS_ALL_CORES, ACCUMULATION_GAS_PER_CORE, CORE_COUNT,
};
use rjam_pvm_core::types::invoke_args::OnTransferInvokeArgs;
use rjam_pvm_hostcall::context::partial_state::{
    AccountSandbox, AccumulatePartialState, StateView,
};
use rjam_pvm_invocation::{
    accumulation::{
        invoke::{accumulate_outer, AccumulationOutputPairs},
        utils::select_deferred_transfers,
    },
    PVMInvocation,
};
use rjam_state::{StateManager, StateMut};
use rjam_types::common::{transfers::DeferredTransfer, workloads::WorkReport};
use std::collections::HashSet;

pub struct AccumulateSummary {
    pub accumulated_reports_count: usize,
    pub deferred_transfers: Vec<DeferredTransfer>,
    pub output_pairs: AccumulationOutputPairs,
}

/// Processes state transitions by `accumulate` PVM invocation.
///
/// # Transitions
///
/// The following state components are copied into `AccumulatePartialState` and then mutated
/// during the `accumulate` PVM invocation by host functions. After executing `accumulate`,
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
/// - `host_yield`
///
/// ### Privileged Services
/// - `host_bless`
///
/// ### Staging Set
/// - `host_designate`
///
/// ### Auth Queue
/// - `host_assign`
pub async fn transition_accumulate_contexts(
    state_manager: &StateManager,
    reports: &[WorkReport],
) -> Result<AccumulateSummary, TransitionError> {
    let always_accumulate_services = &state_manager
        .get_privileged_services()
        .await?
        .always_accumulate_services;

    let gas_limit = ACCUMULATION_GAS_ALL_CORES.max(
        ACCUMULATION_GAS_PER_CORE * CORE_COUNT as UnsignedGas
            + always_accumulate_services.values().sum::<UnsignedGas>(),
    );

    let outer_accumulate_result = accumulate_outer(
        state_manager,
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
        .iter()
    {
        transition_service_accounts(state_manager, service_id, sandbox).await?;
    }

    run_privileged_transitions(state_manager, outer_accumulate_result.partial_state_union).await?;

    Ok(AccumulateSummary {
        accumulated_reports_count: outer_accumulate_result.accumulated_reports_count,
        deferred_transfers: outer_accumulate_result.deferred_transfers,
        output_pairs: outer_accumulate_result.output_pairs,
    })
}

async fn transition_service_accounts(
    state_manager: &StateManager,
    service_id: ServiceId,
    sandbox: &AccountSandbox,
) -> Result<(), TransitionError> {
    match &sandbox.metadata {
        StateView::Entry(new_metadata) => {
            state_manager
                .with_mut_account_metadata(StateMut::Update, service_id, |metadata| {
                    *metadata = new_metadata.clone()
                })
                .await?;
        }
        StateView::Removed => {
            state_manager
                .with_mut_account_metadata(StateMut::Remove, service_id, |_| {})
                .await?;
        }
    }

    // FIXME: handle `Add` case and optimize writes
    for (k, v) in sandbox.storage.iter() {
        match v {
            StateView::Entry(new_entry) => {
                state_manager
                    .with_mut_account_storage_entry(StateMut::Update, service_id, k, |entry| {
                        *entry = new_entry.clone()
                    })
                    .await?;
            }
            StateView::Removed => {
                state_manager
                    .with_mut_account_storage_entry(StateMut::Remove, service_id, k, |_| {})
                    .await?
            }
        }
    }

    for (k, v) in sandbox.preimages.iter() {
        match v {
            StateView::Entry(new_entry) => {
                state_manager
                    .with_mut_account_preimages_entry(StateMut::Update, service_id, k, |entry| {
                        *entry = new_entry.clone()
                    })
                    .await?;
            }
            StateView::Removed => {
                state_manager
                    .with_mut_account_preimages_entry(StateMut::Remove, service_id, k, |_| {})
                    .await?
            }
        }
    }

    for (&k, v) in sandbox.lookups.iter() {
        match v {
            StateView::Entry(new_entry) => {
                state_manager
                    .with_mut_account_lookups_entry(
                        StateMut::Update,
                        service_id,
                        (&k.0, k.1),
                        |entry| *entry = new_entry.clone(),
                    )
                    .await?;
            }
            StateView::Removed => {
                state_manager
                    .with_mut_account_lookups_entry(
                        StateMut::Remove,
                        service_id,
                        (&k.0, k.1),
                        |_| {},
                    )
                    .await?
            }
        }
    }

    Ok(())
}

async fn run_privileged_transitions(
    state_manager: &StateManager,
    partial_state_union: AccumulatePartialState,
) -> Result<(), TransitionError> {
    // Transition staging set
    if let Some(new_staging_set) = partial_state_union.new_staging_set {
        state_manager
            .with_mut_staging_set(StateMut::Update, |staging_set| {
                *staging_set = new_staging_set;
            })
            .await?;
    }

    // Transition auth queue
    if let Some(new_auth_queue) = partial_state_union.new_auth_queue {
        state_manager
            .with_mut_auth_queue(StateMut::Update, |auth_queue| {
                *auth_queue = new_auth_queue;
            })
            .await?;
    }

    // Transition privileged services
    if let Some(new_privileges) = partial_state_union.new_privileges {
        state_manager
            .with_mut_privileged_services(StateMut::Update, |privileges| {
                *privileges = new_privileges;
            })
            .await?;
    }

    Ok(())
}

/// Processes deferred transfers for service accounts.
///
/// This function:
/// 1. Identifies unique destination addresses from the input transfers.
/// 2. For each destination, selects relevant transfers and invokes the PVM `on_transfer` entrypoint.
/// 3. Updates service account states based on the PVM invocation results.
///
/// This function implements the second state transition for service accounts,
/// following the `accumulate` PVM invocation.
pub async fn transition_on_transfer(
    state_manager: &StateManager,
    transfers: Vec<DeferredTransfer>,
) -> Result<(), TransitionError> {
    // Gather all unique destination addresses.
    let destinations: HashSet<ServiceId> = transfers.iter().map(|t| t.to).collect();

    // Invoke PVM `on-transfer` entrypoint for each destination.
    for destination in destinations {
        let transfers = select_deferred_transfers(&transfers, destination);
        PVMInvocation::on_transfer(
            state_manager,
            &OnTransferInvokeArgs {
                destination,
                transfers,
            },
        )
        .await?;
    }

    Ok(())
}
