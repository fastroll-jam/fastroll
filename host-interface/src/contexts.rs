use crate::inner_vm::InnerPVM;
use rjam_codec::{JamDecodeFixed, JamEncode};
use rjam_common::{AccountAddress, DeferredTransfer, Hash32};
use rjam_crypto::utils::blake2b_256;
use rjam_pvm_core::types::{common::ExportDataSegment, error::PVMError};
use rjam_state::state_retriever::StateRetriever;
use rjam_types::state::{
    authorizer::AuthorizerQueue,
    privileged::PrivilegedServices,
    services::{ServiceAccountState, ServiceAccounts},
    timeslot::Timeslot,
    validators::StagingValidatorSet,
};
use std::collections::HashMap;

/// Host context for different invocation types
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_I,                        // IsAuthorized
    X_R(RefineContext),         // Refine
    X_A(AccumulateContextPair), // Accumulate
    X_T(ServiceAccountState),   // OnTransfer
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
    pub x: AccumulateContext,
    pub y: AccumulateContext,
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

#[derive(Clone)]
pub struct AccumulateContext {
    pub(crate) service_account: Option<ServiceAccountState>, // s; current service account
    pub(crate) authorizer_queue: AuthorizerQueue,            // c
    pub(crate) staging_validator_set: StagingValidatorSet,   // v
    pub(crate) new_service_index: AccountAddress,            // i
    pub(crate) deferred_transfers: Vec<DeferredTransfer>,    // t
    pub(crate) new_accounts: ServiceAccounts,                // n
    pub(crate) privileged_services: PrivilegedServices,      // p
}

impl AccumulateContext {
    pub fn initialize_context(
        service_accounts: &ServiceAccounts,
        target_account: &ServiceAccountState,
        target_address: AccountAddress,
    ) -> Result<Self, PVMError> {
        // Get current global state components
        let state_retriever = StateRetriever::new();
        let privileged_services = state_retriever.get_privileged_services()?;
        let authorizer_queue = state_retriever.get_authorizer_queue()?;
        let staging_validator_set = state_retriever.get_staging_validator_set()?;
        let entropy_0 = state_retriever.get_entropy_accumulator()?.current();
        let timeslot = state_retriever.get_recent_timeslot()?;

        let context = Self {
            service_account: Some(target_account.clone()),
            deferred_transfers: vec![],
            new_service_index: Self::new_account_address(
                service_accounts,
                target_address,
                entropy_0,
                timeslot,
            ),
            privileged_services,
            authorizer_queue,
            staging_validator_set,
            new_accounts: ServiceAccounts::default(),
        };

        Ok(context)
    }

    fn new_account_address(
        service_accounts_state: &ServiceAccounts,
        target_address: AccountAddress,
        entropy: Hash32,
        timeslot: Timeslot,
    ) -> AccountAddress {
        // TODO: check return type
        // TODO: confirm how to deal with hash of a tuple; H(address, entropy, timestamp)
        // TODO: check GP appendix B.4.
        let mut buf = vec![];
        target_address.encode_to(&mut buf).unwrap();
        entropy.encode_to(&mut buf).unwrap();
        timeslot.0.encode_to(&mut buf).unwrap();

        let source_hash = blake2b_256(&buf[..]).unwrap();
        let initial_check_address = (u32::decode_fixed(&mut &source_hash[..], 4).unwrap() as u64
            & ((1 << 32) - (1 << 9)) + (1 << 8))
            as AccountAddress;

        service_accounts_state.check(initial_check_address)
    }
}

#[derive(Clone)]
pub struct RefineContext {
    pub(crate) pvm_instances: HashMap<usize, InnerPVM>,
    pub export_segments: Vec<ExportDataSegment>,
    next_instance_id: usize, // PVM instance ID to be assigned for the next instance
}

impl Default for RefineContext {
    fn default() -> Self {
        Self {
            pvm_instances: HashMap::new(),
            export_segments: Vec::new(),
            next_instance_id: 0,
        }
    }
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
