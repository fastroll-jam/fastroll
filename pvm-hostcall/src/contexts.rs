use crate::inner_vm::InnerPVM;
use rjam_codec::{JamDecodeFixed, JamEncode};
use rjam_common::{Address, Balance, Hash32, UnsignedGas};
use rjam_crypto::{hash, Blake2b256};
use rjam_pvm_core::types::{
    common::ExportDataSegment,
    error::{
        HostCallError::{AccountNotFoundInPartialState, AccumulatorAccountNotInitialized},
        PVMError,
    },
};
use rjam_state::StateManager;
use rjam_types::{
    common::transfers::DeferredTransfer,
    state::{
        authorizer::AuthQueue,
        services::{
            AccountInfo, AccountLookupsEntry, AccountMetadata, AccountPreimagesEntry,
            AccountStorageEntry, PrivilegedServices,
        },
        timeslot::Timeslot,
        validators::StagingSet,
    },
};
use std::collections::HashMap;

/// Host context for different invocation types
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_I,                        // IsAuthorized
    X_R(RefineContext),         // Refine
    X_A(AccumulateContextPair), // Accumulate
    X_T,                        // OnTransfer
}

impl InvocationContext {
    pub fn as_refine_context_mut(&mut self) -> Option<&mut RefineContext> {
        if let InvocationContext::X_R(ref mut ctx) = self {
            Some(ctx)
        } else {
            None
        }
    }

    pub fn as_accumulate_context_mut(&mut self) -> Option<&mut AccumulateContextPair> {
        if let InvocationContext::X_A(ref mut pair) = self {
            Some(pair)
        } else {
            None
        }
    }
}

pub struct AccumulateContextPair {
    pub x: Box<AccumulateContext>,
    pub y: Box<AccumulateContext>,
}

impl AccumulateContextPair {
    pub fn get_x(&self) -> &AccumulateContext {
        &self.x
    }

    pub fn get_mut_x(&mut self) -> &mut AccumulateContext {
        &mut self.x
    }

    pub fn get_y(&self) -> &AccumulateContext {
        &self.y
    }

    pub fn get_mut_y(&mut self) -> &mut AccumulateContext {
        &mut self.y
    }
}

/// Represents a service account, including its metadata and associated storage entries.
///
/// This type is primarily used in the accumulate context for state mutations involving service accounts.
/// The global state serialization doesn't require the service metadata and storage entries to be
/// stored together, which makes this type to be specific to the accumulation process.
///
/// TODO: properly manage memory usage for the `HashMap` fields
///
/// Represents type `A` of the GP.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct ServiceAccountCopy {
    pub metadata: AccountMetadata,
    pub storage: HashMap<Hash32, AccountStorageEntry>,
    pub preimages: HashMap<Hash32, AccountPreimagesEntry>,
    pub lookups: HashMap<(Hash32, u32), AccountLookupsEntry>,
}

/// Represents a mutable copy of a subset of the global state used during the accumulation process.
///
/// This provides a sandboxed environment for performing state mutations safely, yielding the final
/// change set of the state on success and discarding the mutations on failure.
#[allow(dead_code)]
#[derive(Clone, Default)]
pub struct AccumulatePartialState {
    pub service_accounts: HashMap<Address, ServiceAccountCopy>, // d; mutated service accounts
    pub staging_set: StagingSet,                                // i
    pub auth_queue: AuthQueue,                                  // q
    pub privileges: PrivilegedServices,                         // x
}

/// Represents the contextual state maintained throughout the accumulation process.
///
/// This provides the necessary state to manage mutations and track changes during the accumulation.
/// The context ensures that state changes are sandboxed and isolated from the global state until
/// they are committed upon successful completion of the accumulation.
///
/// When accessing service accounts that are not subject to mutation, the `StateManager` can be used
/// to retrieve their states. Any newly created or mutated accounts during the accumulation process
/// must first be copied into the `service_accounts` field of the `AccumulatePartialState` to ensure
/// proper isolation.
#[derive(Clone, Default)]
pub struct AccumulateContext {
    pub accumulate_host: Address,              // s
    pub partial_state: AccumulatePartialState, // u
    /// TODO: Check how to manage this context in the parallelized accumulation.
    pub next_new_account_address: Address, // i; used for allocating unique address to a new service
    pub deferred_transfers: Vec<DeferredTransfer>, // t
    pub gas_used: UnsignedGas,
}

impl AccumulateContext {
    pub fn new(
        state_manager: &StateManager,
        target_address: Address,
        entropy: Hash32,
        timeslot: &Timeslot,
    ) -> Result<Self, PVMError> {
        Ok(Self {
            next_new_account_address: AccumulateContext::initialize_new_account_address(
                state_manager,
                target_address,
                entropy,
                timeslot,
            )?,
            ..Default::default()
        })
    }

    pub fn accumulator_account(&self) -> Result<ServiceAccountCopy, PVMError> {
        self.partial_state
            .service_accounts
            .get(&self.accumulate_host)
            .cloned()
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    pub fn accumulator_account_mut(&mut self) -> Result<&mut ServiceAccountCopy, PVMError> {
        self.partial_state
            .service_accounts
            .get_mut(&self.accumulate_host)
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))
    }

    pub fn remove_accumulator_account(&mut self) -> Result<(), PVMError> {
        self.partial_state
            .service_accounts
            .remove(&self.accumulate_host);
        Ok(())
    }

    pub fn account_exists(&self, address: Address) -> Result<bool, PVMError> {
        Ok(self.partial_state.service_accounts.contains_key(&address))
    }

    pub fn get_account_metadata(&self, address: Address) -> Result<AccountMetadata, PVMError> {
        Ok(self
            .partial_state
            .service_accounts
            .get(&address)
            .cloned()
            .ok_or(PVMError::HostCallError(AccountNotFoundInPartialState))?
            .metadata)
    }

    fn initialize_new_account_address(
        state_manager: &StateManager,
        target_address: Address,
        entropy: Hash32,
        timeslot: &Timeslot,
    ) -> Result<Address, PVMError> {
        let mut buf = vec![];
        target_address.encode_to(&mut buf)?;
        entropy.encode_to(&mut buf)?;
        timeslot.0.encode_to(&mut buf)?;

        let source_hash = hash::<Blake2b256>(&buf[..])?;
        let initial_check_address = u32::decode_fixed(&mut &source_hash[..], 4)? as u64
            & (((1 << 32) - (1 << 9)) + (1 << 8));
        let new_account_address = state_manager.check(initial_check_address as Address)?;

        Ok(new_account_address)
    }

    pub fn get_next_new_account_address(&self) -> Address {
        self.next_new_account_address
    }

    #[allow(clippy::redundant_closure_call)]
    pub fn rotate_new_account_address(
        &mut self,
        state_manager: &StateManager,
    ) -> Result<(), PVMError> {
        let bump = |a: Address| -> Address {
            ((a as u64 - (1u64 << 8) + 42) % ((1u64 << 32) - (1u64 << 9)) + (1u64 << 8)) as Address
        };
        self.next_new_account_address = bump(state_manager.check(self.next_new_account_address)?);
        Ok(())
    }

    pub fn add_to_deferred_transfers(&mut self, transfer: DeferredTransfer) {
        self.deferred_transfers.push(transfer);
    }

    pub fn update_privileged_services(
        &mut self,
        manager_service: Address,
        assign_service: Address,
        designate_service: Address,
        always_accumulate_services: HashMap<Address, UnsignedGas>,
    ) -> Result<(), PVMError> {
        self.partial_state.privileges = PrivilegedServices {
            manager_service,
            assign_service,
            designate_service,
            always_accumulate_services,
        };
        Ok(())
    }

    pub fn update_auth_queue(&mut self, auth_queue: AuthQueue) -> Result<(), PVMError> {
        self.partial_state.auth_queue = auth_queue;
        Ok(())
    }

    pub fn update_staging_set(&mut self, staging_set: StagingSet) -> Result<(), PVMError> {
        self.partial_state.staging_set = staging_set;
        Ok(())
    }

    pub fn subtract_accumulator_balance(&mut self, amount: Balance) -> Result<(), PVMError> {
        let account = self
            .partial_state
            .service_accounts
            .get_mut(&self.accumulate_host)
            .ok_or(PVMError::HostCallError(AccountNotFoundInPartialState))?;
        account.metadata.account_info.balance -= amount;
        Ok(())
    }

    pub fn add_new_account(
        &mut self,
        account_info: AccountInfo,
        code_lookups_key: (Hash32, u32),
    ) -> Result<Address, PVMError> {
        let mut new_account = ServiceAccountCopy {
            metadata: AccountMetadata::new(account_info),
            lookups: HashMap::new(),
            ..Default::default()
        };

        // Lookups dictionary entry for the code hash preimage entry
        new_account.lookups.insert(
            code_lookups_key,
            AccountLookupsEntry {
                key: code_lookups_key.0,
                preimage_length: code_lookups_key.1,
                value: vec![],
            },
        );

        let new_account_address = self.next_new_account_address;

        self.partial_state
            .service_accounts
            .insert(new_account_address, new_account);
        Ok(new_account_address)
    }

    pub fn update_accumulator_metadata(
        &mut self,
        code_hash: Hash32,
        gas_limit_accumulate: UnsignedGas,
        gas_limit_on_transfer: UnsignedGas,
    ) -> Result<(), PVMError> {
        let account = self
            .partial_state
            .service_accounts
            .get_mut(&self.accumulate_host)
            .ok_or(PVMError::HostCallError(AccumulatorAccountNotInitialized))?;
        account.metadata.account_info.code_hash = code_hash;
        account.metadata.account_info.gas_limit_accumulate = gas_limit_accumulate;
        account.metadata.account_info.gas_limit_on_transfer = gas_limit_on_transfer;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct RefineContext {
    pub(crate) pvm_instances: HashMap<usize, InnerPVM>,
    pub export_segments: Vec<ExportDataSegment>,
    next_instance_id: usize, // PVM instance ID to be assigned for the next instance
}

impl RefineContext {
    pub(crate) fn add_pvm_instance(&mut self, pvm: InnerPVM) -> usize {
        let id = self.next_instance_id;
        self.pvm_instances.insert(id, pvm);
        self.next_instance_id += 1;
        id
    }

    // TODO: finer-grained instance id management if necessary
    pub(crate) fn remove_pvm_instance(&mut self, id: usize) {
        self.pvm_instances.remove(&id);
    }
}
