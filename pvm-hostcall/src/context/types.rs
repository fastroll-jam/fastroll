use crate::{
    context::partial_state::{
        AccountSandbox, AccountsSandboxMap, AccumulatePartialState, StateView,
    },
    inner_vm::InnerPVM,
};
use rjam_codec::{JamDecodeFixed, JamEncode};
use rjam_common::{Address, Balance, Hash32, UnsignedGas};
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_core::{
    state::memory::Memory,
    types::{
        common::ExportDataSegment,
        error::{HostCallError::*, PVMError},
    },
};
use rjam_state::StateManager;
use rjam_types::{common::transfers::DeferredTransfer, state::*};
use std::collections::HashMap;

pub trait AccountsSandboxHolder {
    // TODO: check if needed
    fn get_accounts_sandbox(&self) -> &AccountsSandboxMap;

    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap;
}

/// Host context for different invocation types
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_I,                            // IsAuthorized
    X_R(RefineHostContext),         // Refine
    X_A(AccumulateHostContextPair), // Accumulate
    X_T(OnTransferHostContext),     // OnTransfer
}

impl InvocationContext {
    fn as_refine_context_mut(&mut self) -> Option<&mut RefineHostContext> {
        if let InvocationContext::X_R(ref mut ctx) = self {
            Some(ctx)
        } else {
            None
        }
    }

    pub fn get_mut_refine_x(&mut self) -> Result<&mut RefineHostContext, PVMError> {
        self.as_refine_context_mut()
            .ok_or(PVMError::HostCallError(InvalidContext))
    }

    // TODO: merge methods?
    fn as_accumulate_context(&self) -> Option<&AccumulateHostContextPair> {
        if let InvocationContext::X_A(ref pair) = self {
            Some(pair)
        } else {
            None
        }
    }

    fn as_accumulate_context_mut(&mut self) -> Option<&mut AccumulateHostContextPair> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair)
        } else {
            None
        }
    }

    pub fn get_accumulate_x(&self) -> Result<&AccumulateHostContext, PVMError> {
        Ok(self
            .as_accumulate_context()
            .ok_or(PVMError::HostCallError(InvalidContext))?
            .get_x())
    }

    pub fn get_mut_accumulate_x(&mut self) -> Result<&mut AccumulateHostContext, PVMError> {
        Ok(self
            .as_accumulate_context_mut()
            .ok_or(PVMError::HostCallError(InvalidContext))?
            .get_mut_x())
    }

    pub fn get_mut_accumulate_y(&mut self) -> Result<&mut AccumulateHostContext, PVMError> {
        Ok(self
            .as_accumulate_context_mut()
            .ok_or(PVMError::HostCallError(InvalidContext))?
            .get_mut_y())
    }

    pub fn as_on_transfer_context_mut(&mut self) -> Option<&mut OnTransferHostContext> {
        if let InvocationContext::X_T(ref mut ctx) = self {
            Some(ctx)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn get_accounts_sandbox(&self) -> Result<&AccountsSandboxMap, PVMError> {
        match self {
            Self::X_A(ctx_pair) => Ok(ctx_pair.get_accounts_sandbox()),
            Self::X_T(ctx) => Ok(ctx.get_accounts_sandbox()),
            _ => Err(PVMError::HostCallError(InvalidContext)),
        }
    }

    pub fn get_mut_accounts_sandbox(&mut self) -> Result<&mut AccountsSandboxMap, PVMError> {
        match self {
            Self::X_A(ctx_pair) => Ok(ctx_pair.get_mut_accounts_sandbox()),
            Self::X_T(ctx) => Ok(ctx.get_mut_accounts_sandbox()),
            _ => Err(PVMError::HostCallError(InvalidContext)),
        }
    }
}

/// Represents the contextual state maintained throughout the `on_transfer` process.
#[derive(Clone, Default)]
pub struct OnTransferHostContext {
    pub accounts_sandbox: AccountsSandboxMap,
}

impl AccountsSandboxHolder for OnTransferHostContext {
    fn get_accounts_sandbox(&self) -> &AccountsSandboxMap {
        &self.accounts_sandbox
    }

    fn get_mut_accounts_sandbox(&mut self) -> &mut AccountsSandboxMap {
        &mut self.accounts_sandbox
    }
}

impl OnTransferHostContext {
    pub async fn new(state_manager: &StateManager, recipient: Address) -> Result<Self, PVMError> {
        let mut accounts_sandbox = HashMap::new();
        let recipient_account_sandbox =
            AccountSandbox::from_address(state_manager, recipient).await?;
        accounts_sandbox.insert(recipient, recipient_account_sandbox);
        Ok(Self {
            accounts_sandbox: AccountsSandboxMap {
                accounts: accounts_sandbox,
            },
        })
    }
}

pub struct AccumulateHostContextPair {
    pub x: Box<AccumulateHostContext>,
    pub y: Box<AccumulateHostContext>,
}

impl AccountsSandboxHolder for AccumulateHostContextPair {
    fn get_accounts_sandbox(&self) -> &AccountsSandboxMap {
        &self.x.partial_state.accounts_sandbox
    }

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
    pub accumulate_host: Address,              // s
    pub partial_state: AccumulatePartialState, // u
    /// TODO: Check how to manage this context in the parallelized accumulation.
    pub next_new_account_address: Address, // i; used for allocating unique address to a new service
    pub deferred_transfers: Vec<DeferredTransfer>, // t
    pub yielded_accumulate_hash: Option<Hash32>, // y
    pub gas_used: UnsignedGas,
}

impl AccumulateHostContext {
    pub async fn new(
        state_manager: &StateManager,
        accumulate_address: Address,
        entropy: Hash32,
        timeslot: &Timeslot,
    ) -> Result<Self, PVMError> {
        Ok(Self {
            next_new_account_address: Self::initialize_new_account_address(
                state_manager,
                accumulate_address,
                entropy,
                timeslot,
            )
            .await?,
            partial_state: AccumulatePartialState::new_from_address(
                state_manager,
                accumulate_address,
            )
            .await?,
            ..Default::default()
        })
    }

    async fn initialize_new_account_address(
        state_manager: &StateManager,
        accumulate_address: Address,
        entropy: Hash32,
        timeslot: &Timeslot,
    ) -> Result<Address, PVMError> {
        let mut buf = vec![];
        accumulate_address.encode_to(&mut buf)?;
        entropy.encode_to(&mut buf)?;
        timeslot.0.encode_to(&mut buf)?;

        let source_hash = hash::<Blake2b256>(&buf[..])?;
        let modulus = (1u64 << 32) - (1 << 9);
        let initial_check_address =
            (u64::decode_fixed(&mut &source_hash[..], 4)? % modulus) + (1 << 8);
        let new_account_address = state_manager
            .check(initial_check_address as Address)
            .await?;

        Ok(new_account_address)
    }

    pub async fn copy_account_to_partial_state_sandbox(
        &mut self,
        state_manager: &StateManager,
        address: Address,
    ) -> Result<(), PVMError> {
        let account_copy = AccountSandbox::from_address(state_manager, address).await?;
        self.partial_state
            .accounts_sandbox
            .insert(address, account_copy);

        Ok(())
    }

    pub async fn get_accumulator_metadata(
        &mut self,
        state_manager: &StateManager,
    ) -> Result<&AccountMetadata, PVMError> {
        self.partial_state
            .accounts_sandbox
            .get_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    pub async fn get_mut_accumulator_metadata(
        &mut self,
        state_manager: &StateManager,
    ) -> Result<&mut AccountMetadata, PVMError> {
        self.partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    // TODO: should return reference?
    pub fn accumulator_account(&self) -> Result<AccountSandbox, PVMError> {
        self.partial_state
            .accounts_sandbox
            .get(&self.accumulate_host)
            .cloned()
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    pub fn accumulator_account_mut(&mut self) -> Result<&mut AccountSandbox, PVMError> {
        self.partial_state
            .accounts_sandbox
            .get_mut(&self.accumulate_host)
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    pub fn remove_accumulator_account(&mut self) -> Result<(), PVMError> {
        self.partial_state
            .accounts_sandbox
            .remove(&self.accumulate_host);
        Ok(())
    }

    pub fn get_next_new_account_address(&self) -> Address {
        self.next_new_account_address
    }

    #[allow(clippy::redundant_closure_call)]
    pub async fn rotate_new_account_address(
        &mut self,
        state_manager: &StateManager,
    ) -> Result<(), PVMError> {
        let bump = |a: Address| -> Address {
            let modulus = (1u64 << 32) - (1u64 << 9);
            ((a as u64 - (1u64 << 8) + 42) % modulus + (1u64 << 8)) as Address
        };
        self.next_new_account_address =
            bump(state_manager.check(self.next_new_account_address).await?);
        Ok(())
    }

    pub fn add_to_deferred_transfers(&mut self, transfer: DeferredTransfer) {
        self.deferred_transfers.push(transfer);
    }

    pub fn assign_new_privileged_services(
        &mut self,
        manager_service: Address,
        assign_service: Address,
        designate_service: Address,
        always_accumulate_services: HashMap<Address, UnsignedGas>,
    ) -> Result<(), PVMError> {
        self.partial_state.new_privileges = Some(PrivilegedServices {
            manager_service,
            assign_service,
            designate_service,
            always_accumulate_services,
        });
        Ok(())
    }

    pub fn assign_new_auth_queue(&mut self, auth_queue: AuthQueue) -> Result<(), PVMError> {
        self.partial_state.new_auth_queue = Some(auth_queue);
        Ok(())
    }

    pub fn assign_new_staging_set(&mut self, staging_set: StagingSet) -> Result<(), PVMError> {
        self.partial_state.new_staging_set = Some(staging_set);
        Ok(())
    }

    pub async fn subtract_accumulator_balance(
        &mut self,
        state_manager: &StateManager,
        amount: Balance,
    ) -> Result<(), PVMError> {
        let account_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))?;

        // Explicitly checked from callsites (host functions) that this has positive value.
        account_metadata.account_info.balance -= amount;
        Ok(())
    }

    pub async fn add_accumulator_balance(
        &mut self,
        state_manager: &StateManager,
        amount: Balance,
    ) -> Result<(), PVMError> {
        let account_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))?;

        // TODO: check overflow
        account_metadata.account_info.balance += amount;
        Ok(())
    }

    pub async fn add_new_account(
        &mut self,
        state_manager: &StateManager,
        account_info: AccountInfo,
        code_lookups_key: (Hash32, u32),
    ) -> Result<Address, PVMError> {
        let new_account = AccountSandbox {
            metadata: StateView::Entry(AccountMetadata::new(account_info)),
            storage: HashMap::new(),
            preimages: HashMap::new(),
            lookups: HashMap::new(),
        };

        let new_account_address = self.next_new_account_address;
        self.partial_state
            .accounts_sandbox
            .insert(new_account_address, new_account);

        // Lookups dictionary entry for the code hash preimage entry
        let code_lookups_entry = AccountLookupsEntry { value: vec![] };

        self.partial_state
            .accounts_sandbox
            .insert_account_lookups_entry(
                state_manager,
                new_account_address,
                code_lookups_key,
                code_lookups_entry,
            )
            .await?;

        Ok(new_account_address)
    }

    pub async fn update_accumulator_metadata(
        &mut self,
        state_manager: &StateManager,
        code_hash: Hash32,
        gas_limit_accumulate: UnsignedGas,
        gas_limit_on_transfer: UnsignedGas,
    ) -> Result<(), PVMError> {
        let accumulator_metadata = self
            .partial_state
            .accounts_sandbox
            .get_mut_account_metadata(state_manager, self.accumulate_host)
            .await?
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))?;

        accumulator_metadata.account_info.code_hash = code_hash;
        accumulator_metadata.account_info.gas_limit_accumulate = gas_limit_accumulate;
        accumulator_metadata.account_info.gas_limit_on_transfer = gas_limit_on_transfer;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct RefineHostContext {
    /// Inner PVM instances
    pub(crate) pvm_instances: HashMap<usize, InnerPVM>,
    /// PVM instance ID to be assigned for the next instance
    pub next_instance_id: usize,
    /// Export data segments
    pub export_segments: Vec<ExportDataSegment>,
    /// Lookup anchor timeslot; copied from `RefinementContext`
    pub lookup_anchor_timeslot: u32,
    /// Import data segments
    pub import_segments: Vec<ExportDataSegment>,
    /// Export data segments index
    pub export_segments_offset: usize,
}

impl RefineHostContext {
    pub fn new(
        lookup_anchor_timeslot: u32,
        import_segments: Vec<ExportDataSegment>,
        export_segments_offset: usize,
    ) -> Self {
        Self {
            lookup_anchor_timeslot,
            import_segments,
            export_segments_offset,
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
