use crate::{
    context::partial_state::{
        AccountSandbox, AccountsSandboxMap, AccumulatePartialState, SandboxEntryVersioned,
    },
    error::HostCallError,
    inner_vm::InnerPVM,
};
use fr_codec::prelude::*;
use fr_common::{
    Balance, CodeHash, EntropyHash, LookupsKey, Octets, ServiceId, TimeslotIndex, UnsignedGas,
    CORE_COUNT, MIN_PUBLIC_SERVICE_ID,
};
use fr_crypto::{hash, Blake2b256};
use fr_limited_vec::FixedVec;
use fr_pvm_core::state::memory::Memory;
use fr_pvm_types::{
    common::ExportDataSegment,
    invoke_args::{
        AccumulateInvokeArgs, DeferredTransfer, IsAuthorizedInvokeArgs, RefineInvokeArgs,
    },
    invoke_results::AccumulationOutputHash,
};
use fr_state::{
    provider::HostStateProvider,
    types::{AccountLookupsEntry, AccountLookupsEntryExt, AccountMetadata, AuthQueue, StagingSet},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
};

pub mod partial_state;

pub trait AccountsSandboxHolder<S: HostStateProvider> {
    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap<S>;
}

/// Host context for different invocation types
#[allow(non_camel_case_types)]
#[allow(clippy::large_enum_variant)]
pub enum InvocationContext<S: HostStateProvider> {
    /// `is_authorized` host-call context (no context)
    X_I(IsAuthorizedHostContext),
    /// `refine` host-call context
    X_R(RefineHostContext),
    /// `accumulate` host-call context pair
    X_A(AccumulateHostContextPair<S>),
}

impl<S: HostStateProvider> InvocationContext<S> {
    pub fn get_refine_x(&mut self) -> Option<&RefineHostContext> {
        if let InvocationContext::X_R(ref ctx) = self {
            Some(ctx)
        } else {
            None
        }
    }

    pub fn get_mut_refine_x(&mut self) -> Option<&mut RefineHostContext> {
        if let InvocationContext::X_R(ref mut ctx) = self {
            Some(ctx)
        } else {
            None
        }
    }

    pub fn get_accumulate_x(&self) -> Option<&AccumulateHostContext<S>> {
        if let InvocationContext::X_A(ref pair) = self {
            Some(pair.get_x())
        } else {
            None
        }
    }

    pub fn get_mut_accumulate_x(&mut self) -> Option<&mut AccumulateHostContext<S>> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair.get_mut_x())
        } else {
            None
        }
    }

    pub fn get_mut_accumulate_y(&mut self) -> Option<&mut AccumulateHostContext<S>> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair.get_mut_y())
        } else {
            None
        }
    }

    pub fn get_mut_accounts_sandbox(&mut self) -> Option<&mut AccountsSandboxMap<S>> {
        match self {
            Self::X_A(ctx_pair) => Some(ctx_pair.get_mut_accounts_sandbox()),
            _ => None,
        }
    }
}

/// `is_authorized` host state context, which holds invoke args only.
pub struct IsAuthorizedHostContext {
    /// IsAuthorized entry-point function invocation args (read-only)
    pub invoke_args: IsAuthorizedInvokeArgs,
}

impl IsAuthorizedHostContext {
    pub fn new(invoke_args: IsAuthorizedInvokeArgs) -> Self {
        Self { invoke_args }
    }
}

pub struct AccumulateHostContextPair<S: HostStateProvider> {
    pub x: Box<AccumulateHostContext<S>>,
    pub y: Box<AccumulateHostContext<S>>,
}

impl<S> AccountsSandboxHolder<S> for AccumulateHostContextPair<S>
where
    S: HostStateProvider,
{
    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap<S> {
        &mut self.x.partial_state.accounts_sandbox
    }
}

impl<S: HostStateProvider> AccumulateHostContextPair<S> {
    pub fn get_x(&self) -> &AccumulateHostContext<S> {
        &self.x
    }

    pub fn get_mut_x(&mut self) -> &mut AccumulateHostContext<S> {
        &mut self.x
    }

    pub fn get_y(&self) -> &AccumulateHostContext<S> {
        &self.y
    }

    pub fn get_mut_y(&mut self) -> &mut AccumulateHostContext<S> {
        &mut self.y
    }
}

/// Represents the contextual state maintained throughout the `accumulate` process.
///
/// This provides the necessary state to manage mutations and track changes during the accumulation.
/// The context ensures that state changes are sandboxed and isolated from the global state until
/// they are committed upon successful completion of the accumulation.
///
/// When accessing service accounts that are not subject to mutation, the `StateManager` can be used
/// to retrieve their states. Any newly created or mutated accounts during the accumulation process
/// must first be copied into the `accounts_sandbox` field of the `AccumulatePartialState` to ensure
/// proper isolation.
#[derive(Default)]
pub struct AccumulateHostContext<S: HostStateProvider> {
    /// `s`: Accumulate host service account index
    pub accumulate_host: ServiceId,
    /// **`u`**: Global state partially copied as an accumulation context
    pub partial_state: AccumulatePartialState<S>,
    /// `i`: Next new service account index, carefully chosen to avoid collision.
    /// In the parallelized accumulation context, each single-service accumulation has different
    /// initial values for this since accumulate host service id is used as input of the `check` function.
    pub next_new_service_id: ServiceId,
    /// **`t`**: Deferred token transfers
    pub deferred_transfers: Vec<DeferredTransfer>,
    /// `y`: Accumulation result hash
    pub yielded_accumulate_hash: Option<AccumulationOutputHash>,
    /// **`p`**: Provided preimage data
    pub provided_preimages: HashSet<(ServiceId, Octets)>,
    /// Accumulate entry-point function invocation args (read-only)
    pub invoke_args: AccumulateInvokeArgs,
    /// Current entropy value (`η0′`)
    pub curr_entropy: EntropyHash,
}

impl<S: HostStateProvider> Clone for AccumulateHostContext<S> {
    fn clone(&self) -> Self {
        Self {
            accumulate_host: self.accumulate_host,
            partial_state: self.partial_state.clone(),
            next_new_service_id: self.next_new_service_id,
            deferred_transfers: self.deferred_transfers.clone(),
            yielded_accumulate_hash: self.yielded_accumulate_hash.clone(),
            provided_preimages: self.provided_preimages.clone(),
            invoke_args: self.invoke_args.clone(),
            curr_entropy: self.curr_entropy.clone(),
        }
    }
}

impl<S: HostStateProvider> AccumulateHostContext<S> {
    pub async fn new(
        state_manager: Arc<S>,
        partial_state: AccumulatePartialState<S>,
        accumulate_host: ServiceId,
        curr_entropy: EntropyHash,
        timeslot_index: TimeslotIndex,
        invoke_args: AccumulateInvokeArgs,
    ) -> Result<Self, HostCallError> {
        Ok(Self {
            next_new_service_id: Self::initialize_new_service_id(
                state_manager,
                accumulate_host,
                curr_entropy.clone(),
                timeslot_index,
            )
            .await?,
            accumulate_host,
            partial_state,
            deferred_transfers: Vec::new(),
            yielded_accumulate_hash: None,
            provided_preimages: HashSet::new(),
            invoke_args,
            curr_entropy,
        })
    }

    async fn initialize_new_service_id(
        state_manager: Arc<S>,
        accumulate_host: ServiceId,
        entropy: EntropyHash,
        timeslot_index: TimeslotIndex,
    ) -> Result<ServiceId, HostCallError> {
        let mut buf = vec![];
        accumulate_host.encode_to(&mut buf)?;
        entropy.encode_to(&mut buf)?;
        timeslot_index.encode_to(&mut buf)?;
        let source_hash = hash::<Blake2b256>(&buf[..])?;
        let hash_as_u64 = u64::decode_fixed(&mut &source_hash[..], 4)?;

        let s = MIN_PUBLIC_SERVICE_ID as u64;
        let modulus = (1u64 << 32) - s - (1 << 8);
        let initial_check_id = (hash_as_u64 % modulus)
            .checked_add(s)
            .ok_or(HostCallError::ServiceIdOverflow)?;
        let new_service_id = state_manager.check(initial_check_id as ServiceId).await?;
        Ok(new_service_id)
    }

    pub async fn get_accumulator_metadata(
        &mut self,
        state_manager: Arc<S>,
    ) -> Result<&AccountMetadata, HostCallError> {
        self.partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)
    }

    #[allow(clippy::redundant_closure_call)]
    pub async fn rotate_new_account_id(
        &mut self,
        state_manager: Arc<S>,
    ) -> Result<(), HostCallError> {
        let s = MIN_PUBLIC_SERVICE_ID as u64;
        let bump = |prev_next_new_id: ServiceId| -> ServiceId {
            let modulus = (1u64 << 32) - s - (1u64 << 8);
            ((prev_next_new_id as u64 - s + 42) % modulus + s) as ServiceId
        };
        self.next_new_service_id = state_manager.check(bump(self.next_new_service_id)).await?;
        Ok(())
    }

    pub fn add_to_deferred_transfers(&mut self, transfer: DeferredTransfer) {
        self.deferred_transfers.push(transfer);
    }

    pub fn assign_new_privileged_services(
        &mut self,
        manager_service: ServiceId,
        assign_services: FixedVec<ServiceId, CORE_COUNT>,
        designate_service: ServiceId,
        registrar_service: ServiceId,
        always_accumulate_services: BTreeMap<ServiceId, UnsignedGas>,
    ) {
        self.partial_state.manager_service = manager_service;
        self.partial_state.assign_services = assign_services;
        self.partial_state.designate_service = designate_service;
        self.partial_state.registrar_service = registrar_service;
        self.partial_state.always_accumulate_services = always_accumulate_services;
    }

    pub fn assign_new_core_assign_service(&mut self, core_index: usize, assign_service: ServiceId) {
        self.partial_state.assign_services[core_index] = assign_service;
    }

    pub fn assign_new_auth_queue(&mut self, auth_queue: AuthQueue) {
        self.partial_state.new_auth_queue = Some(auth_queue);
    }

    pub fn assign_new_staging_set(&mut self, staging_set: StagingSet) {
        self.partial_state.new_staging_set = Some(staging_set);
    }

    pub async fn subtract_accumulator_balance(
        &mut self,
        state_manager: Arc<S>,
        amount: Balance,
    ) -> Result<(), HostCallError> {
        let account_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager.clone(), self.accumulate_host)
            .await?
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)?;

        // Explicitly checked from callsites (host functions) that this has positive value.
        account_metadata.balance -= amount;
        self.partial_state
            .accounts_sandbox
            .mark_account_metadata_updated(state_manager, self.accumulate_host)
            .await?;

        Ok(())
    }

    pub async fn add_accumulator_balance(
        &mut self,
        state_manager: Arc<S>,
        amount: Balance,
    ) -> Result<(), HostCallError> {
        let account_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager.clone(), self.accumulate_host)
            .await?
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)?;

        account_metadata
            .balance
            .checked_add(amount)
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)?;
        self.partial_state
            .accounts_sandbox
            .mark_account_metadata_updated(state_manager, self.accumulate_host)
            .await?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_new_account(
        &mut self,
        state_manager: Arc<S>,
        code_hash: CodeHash,
        balance: Balance,
        gas_limit_accumulate: UnsignedGas,
        gas_limit_on_transfer: UnsignedGas,
        code_lookups_key: LookupsKey,
        gratis_storage_offset: Balance,
        created_at: TimeslotIndex,
        last_accumulate_at: TimeslotIndex,
        parent_service_id: ServiceId,
    ) -> Result<ServiceId, HostCallError> {
        let new_service_id = self.next_new_service_id;

        let new_account = AccountSandbox {
            metadata: SandboxEntryVersioned::new_added(AccountMetadata {
                code_hash,
                balance,
                gas_limit_accumulate,
                gas_limit_on_transfer,
                octets_footprint: 0,
                gratis_storage_offset,
                items_footprint: 0,
                created_at,
                last_accumulate_at,
                parent_service_id,
            }),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
            _phantom: PhantomData,
        };

        self.partial_state
            .accounts_sandbox
            .insert(new_service_id, new_account);

        // Lookups dictionary entry for the code hash preimage entry
        let code_lookups_entry = AccountLookupsEntryExt::from_entry(
            code_lookups_key.clone(),
            AccountLookupsEntry::default(),
        );

        self.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_manager,
                new_service_id,
                code_lookups_key,
                code_lookups_entry,
            )
            .await?;

        Ok(new_service_id)
    }

    pub async fn update_accumulator_metadata(
        &mut self,
        state_manager: Arc<S>,
        code_hash: CodeHash,
        gas_limit_accumulate: UnsignedGas,
        gas_limit_on_transfer: UnsignedGas,
    ) -> Result<(), HostCallError> {
        let accumulator_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager.clone(), self.accumulate_host)
            .await?
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)?;

        accumulator_metadata.code_hash = code_hash;
        accumulator_metadata.gas_limit_accumulate = gas_limit_accumulate;
        accumulator_metadata.gas_limit_on_transfer = gas_limit_on_transfer;

        self.partial_state
            .accounts_sandbox
            .mark_account_metadata_updated(state_manager, self.accumulate_host)
            .await?;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct RefineHostContext {
    /// PVM instance ID to be assigned for the next instance
    pub next_instance_id: usize,
    /// **`m`**: Inner PVM instances
    pub(crate) pvm_instances: HashMap<usize, InnerPVM>,
    /// **`e`**: Export data segments
    pub export_segments: Vec<ExportDataSegment>,
    /// Entropy value that can be used in off-chain refine stage
    /// TODO: inject proper refine entropy (placeholder for now)
    pub refine_entropy: EntropyHash,
    /// Refine entry-point function invocation args (read-only)
    pub invoke_args: RefineInvokeArgs,
}

impl RefineHostContext {
    pub fn new_with_invoke_args(invoke_args: RefineInvokeArgs) -> Self {
        Self {
            invoke_args,
            ..Default::default()
        }
    }

    pub fn get_inner_vm_memory(&self, vm_instance_id: usize) -> Option<&Memory> {
        self.pvm_instances.get(&vm_instance_id).map(|vm| &vm.memory)
    }

    pub fn get_mut_inner_vm_memory(&mut self, vm_instance_id: usize) -> Option<&mut Memory> {
        self.pvm_instances
            .get_mut(&vm_instance_id)
            .map(|vm| &mut vm.memory)
    }

    pub(crate) fn add_pvm_instance(&mut self, pvm: InnerPVM) -> usize {
        let id = self.next_instance_id;
        self.pvm_instances.insert(id, pvm);
        self.next_instance_id += 1;
        id
    }

    pub(crate) fn remove_pvm_instance(&mut self, id: usize) {
        self.pvm_instances.remove(&id);
    }
}
