use crate::{
    context::partial_state::{
        AccountSandbox, AccountsSandboxMap, AccumulatePartialState, SandboxEntry,
    },
    error::HostCallError,
    inner_vm::InnerPVM,
};
use fr_codec::prelude::*;
use fr_common::{Balance, Hash32, LookupsKey, Octets, ServiceId, UnsignedGas};
use fr_crypto::{hash, Blake2b256};
use fr_pvm_core::state::memory::Memory;
use fr_pvm_types::{
    common::ExportDataSegment,
    invoke_args::{
        AccumulateInvokeArgs, DeferredTransfer, IsAuthorizedInvokeArgs, OnTransferInvokeArgs,
        RefineInvokeArgs,
    },
};
use fr_state::{
    manager::StateManager,
    types::{
        AccountLookupsEntry, AccountLookupsEntryExt, AccountMetadata, AuthQueue,
        PrivilegedServices, StagingSet,
    },
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

pub mod partial_state;

pub trait AccountsSandboxHolder {
    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap;
}

/// Host context for different invocation types
#[allow(non_camel_case_types)]
#[allow(clippy::large_enum_variant)]
pub enum InvocationContext {
    /// `is_authorized` host-call context (no context)
    X_I(IsAuthorizedHostContext),
    /// `refine` host-call context
    X_R(RefineHostContext),
    /// `accumulate` host-call context pair
    X_A(AccumulateHostContextPair),
    /// `on_transfer` host-call context
    X_T(OnTransferHostContext),
}

impl InvocationContext {
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

    pub fn get_accumulate_x(&self) -> Option<&AccumulateHostContext> {
        if let InvocationContext::X_A(ref pair) = self {
            Some(pair.get_x())
        } else {
            None
        }
    }

    pub fn get_mut_accumulate_x(&mut self) -> Option<&mut AccumulateHostContext> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair.get_mut_x())
        } else {
            None
        }
    }

    pub fn get_mut_accumulate_y(&mut self) -> Option<&mut AccumulateHostContext> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair.get_mut_y())
        } else {
            None
        }
    }

    pub fn get_mut_accounts_sandbox(&mut self) -> Option<&mut AccountsSandboxMap> {
        match self {
            Self::X_A(ctx_pair) => Some(ctx_pair.get_mut_accounts_sandbox()),
            Self::X_T(ctx) => Some(ctx.get_mut_accounts_sandbox()),
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

/// Represents the contextual state maintained throughout the `on_transfer` process.
#[derive(Clone, Default)]
pub struct OnTransferHostContext {
    pub accounts_sandbox: AccountsSandboxMap,
    /// OnTransfer entry-point function invocation args (read-only)
    pub invoke_args: OnTransferInvokeArgs,
    /// Current entropy value (`η0′`)
    pub curr_entropy: Hash32,
}

impl AccountsSandboxHolder for OnTransferHostContext {
    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap {
        &mut self.accounts_sandbox
    }
}

impl OnTransferHostContext {
    pub async fn new(
        state_manager: Arc<StateManager>,
        recipient: ServiceId,
        curr_entropy: Hash32,
        invoke_args: OnTransferInvokeArgs,
    ) -> Result<Self, HostCallError> {
        let mut accounts_sandbox = AccountsSandboxMap::default();
        let recipient_account_sandbox =
            AccountSandbox::from_service_id(state_manager, recipient).await?;
        accounts_sandbox.insert(recipient, recipient_account_sandbox);
        Ok(Self {
            accounts_sandbox,
            invoke_args,
            curr_entropy,
        })
    }
}

pub struct AccumulateHostContextPair {
    pub x: Box<AccumulateHostContext>,
    pub y: Box<AccumulateHostContext>,
}

impl AccountsSandboxHolder for AccumulateHostContextPair {
    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap {
        &mut self.x.partial_state.accounts_sandbox
    }
}

impl AccumulateHostContextPair {
    pub fn get_x(&self) -> &AccumulateHostContext {
        &self.x
    }

    pub fn get_mut_x(&mut self) -> &mut AccumulateHostContext {
        &mut self.x
    }

    pub fn get_y(&self) -> &AccumulateHostContext {
        &self.y
    }

    pub fn get_mut_y(&mut self) -> &mut AccumulateHostContext {
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
#[derive(Clone, Default)]
pub struct AccumulateHostContext {
    /// `s`: Accumulate host service account index
    pub accumulate_host: ServiceId,
    /// **`u`**: Global state partially copied as an accumulation context
    pub partial_state: AccumulatePartialState,
    /// TODO: Check how to manage this context in the parallelized accumulation.
    /// `i`: Next new service account index, carefully chosen to avoid collision
    pub next_new_service_id: ServiceId,
    /// **`t`**: Deferred token transfers
    pub deferred_transfers: Vec<DeferredTransfer>,
    /// `y`: Accumulation result hash
    pub yielded_accumulate_hash: Option<Hash32>,
    /// **`p`**: Provided preimage data
    pub provided_preimages: HashSet<(ServiceId, Octets)>,
    /// Accumulate entry-point function invocation args (read-only)
    pub invoke_args: AccumulateInvokeArgs,
    /// Current entropy value (`η0′`)
    pub curr_entropy: Hash32,
}

impl AccumulateHostContext {
    pub async fn new(
        state_manager: Arc<StateManager>,
        partial_state: AccumulatePartialState,
        accumulate_host: ServiceId,
        curr_entropy: Hash32,
        timeslot_index: u32,
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
            invoke_args,
            curr_entropy,
            ..Default::default()
        })
    }

    async fn initialize_new_service_id(
        state_manager: Arc<StateManager>,
        accumulate_host: ServiceId,
        entropy: Hash32,
        timeslot_index: u32,
    ) -> Result<ServiceId, HostCallError> {
        let mut buf = vec![];
        accumulate_host.encode_to(&mut buf)?;
        entropy.encode_to(&mut buf)?;
        timeslot_index.encode_to(&mut buf)?;

        let source_hash = hash::<Blake2b256>(&buf[..])?;
        let hash_as_u64 = u64::decode_fixed(&mut &source_hash[..], 4)?;
        let modulus = (1u64 << 32) - (1 << 9);
        let initial_check_id = (hash_as_u64 % modulus)
            .checked_add(1 << 8)
            .ok_or(HostCallError::ServiceIdOverflow)?;
        let new_service_id = state_manager.check(initial_check_id as ServiceId).await?;

        Ok(new_service_id)
    }

    pub async fn get_accumulator_metadata(
        &mut self,
        state_manager: Arc<StateManager>,
    ) -> Result<&AccountMetadata, HostCallError> {
        self.partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(HostCallError::AccumulatorAccountNotInitialized)
    }

    #[allow(clippy::redundant_closure_call)]
    pub async fn rotate_new_account_index(
        &mut self,
        state_manager: Arc<StateManager>,
    ) -> Result<(), HostCallError> {
        let bump = |a: ServiceId| -> ServiceId {
            let modulus = (1u64 << 32) - (1u64 << 9);
            ((a as u64 - (1u64 << 8) + 42) % modulus + (1u64 << 8)) as ServiceId
        };
        self.next_new_service_id = bump(state_manager.check(self.next_new_service_id).await?);
        Ok(())
    }

    pub fn add_to_deferred_transfers(&mut self, transfer: DeferredTransfer) {
        self.deferred_transfers.push(transfer);
    }

    pub fn assign_new_privileged_services(
        &mut self,
        manager_service: ServiceId,
        assign_service: ServiceId,
        designate_service: ServiceId,
        always_accumulate_services: BTreeMap<ServiceId, UnsignedGas>,
    ) {
        self.partial_state.new_privileges = Some(PrivilegedServices {
            manager_service,
            assign_service,
            designate_service,
            always_accumulate_services,
        });
    }

    pub fn assign_new_auth_queue(&mut self, auth_queue: AuthQueue) {
        self.partial_state.new_auth_queue = Some(auth_queue);
    }

    pub fn assign_new_staging_set(&mut self, staging_set: StagingSet) {
        self.partial_state.new_staging_set = Some(staging_set);
    }

    pub async fn subtract_accumulator_balance(
        &mut self,
        state_manager: Arc<StateManager>,
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
        state_manager: Arc<StateManager>,
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

    pub async fn add_new_account(
        &mut self,
        state_manager: Arc<StateManager>,
        code_hash: Hash32,
        balance: Balance,
        gas_limit_accumulate: UnsignedGas,
        gas_limit_on_transfer: UnsignedGas,
        code_lookups_key: LookupsKey,
    ) -> Result<ServiceId, HostCallError> {
        let new_service_id = self.next_new_service_id;

        let new_account = AccountSandbox {
            metadata: SandboxEntry::new_added(AccountMetadata {
                code_hash,
                balance,
                gas_limit_accumulate,
                gas_limit_on_transfer,
                items_footprint: 0,
                octets_footprint: 0,
            }),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
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
        state_manager: Arc<StateManager>,
        code_hash: Hash32,
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
    pub refine_entropy: Hash32,
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
