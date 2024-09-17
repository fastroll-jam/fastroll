use crate::inner_vm::InnerPVM;
use jam_codec::{JamDecodeFixed, JamEncode};
use jam_common::{AccountAddress, Hash32, Octets};
use jam_crypto::utils::blake2b_256;
use jam_pvm_core::types::{accumulation::DeferredTransfer, error::HostCallError};
use jam_state::state_retriever::StateRetriever;
use jam_types::state::{
    authorizer::AuthorizerQueue,
    privileged::PrivilegedServices,
    services::{ServiceAccountState, ServiceAccounts},
    timeslot::Timeslot,
    validators::StagingValidatorSet,
};
use std::collections::HashMap;

#[derive(Clone)]
#[allow(non_camel_case_types)]
pub enum InvocationContext {
    X_G(GeneralContext),                             // General Functions
    X_I,                                             // Is-Authorized
    X_R(RefinementContext),                          // Refine
    X_A((AccumulationContext, AccumulationContext)), // Accumulate
    X_T,                                             // On-Transfer
}

#[derive(Clone)]
pub struct GeneralContext {
    pub(crate) invoker_account: ServiceAccountState, // s; current service account
    pub(crate) invoker_address: AccountAddress,      // s (light font)
    pub(crate) service_accounts: Option<ServiceAccounts>, // d
}

#[derive(Clone)]
pub struct AccumulationContext {
    pub(crate) service_account: Option<ServiceAccountState>, // s; current service account
    pub(crate) authorizer_queue: AuthorizerQueue,            // c
    pub(crate) staging_validator_set: StagingValidatorSet,   // v
    pub(crate) new_service_index: AccountAddress,            // i
    pub(crate) deferred_transfers: Vec<DeferredTransfer>,    // t
    pub(crate) new_accounts: ServiceAccounts,                // n
    pub(crate) privileged_services: PrivilegedServices,      // p
}

impl AccumulationContext {
    pub fn initialize_context_pair(
        service_accounts: &ServiceAccounts,
        invoker_account: ServiceAccountState,
        invoker_address: AccountAddress,
    ) -> Result<(Self, Self), HostCallError> {
        // Get current global state components
        let state_retriever = StateRetriever::new();
        let privileged_services = state_retriever.get_privileged_services()?;
        let authorizer_queue = state_retriever.get_authorizer_queue()?;
        let staging_validator_set = state_retriever.get_staging_validator_set()?;
        let entropy_0 = state_retriever.get_entropy_accumulator()?.current();
        let timeslot = state_retriever.get_recent_timeslot()?;

        let context = Self {
            service_account: Some(invoker_account),
            deferred_transfers: vec![],
            new_service_index: Self::new_account_address(
                service_accounts,
                invoker_address,
                entropy_0,
                timeslot,
            ),
            privileged_services,
            authorizer_queue,
            staging_validator_set,
            new_accounts: ServiceAccounts::default(),
        };

        Ok((context.clone(), context))
    }

    fn new_account_address(
        service_accounts_state: &ServiceAccounts,
        invoker_address: AccountAddress,
        entropy: Hash32,
        timeslot: Timeslot,
    ) -> AccountAddress {
        // TODO: check return type
        // TODO: confirm how to deal with hash of a tuple; H(address, entropy, timestamp)
        // TODO: check GP appendix B.4.
        let mut buf = vec![];
        invoker_address.encode_to(&mut buf).unwrap();
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
pub struct RefinementContext {
    pub(crate) pvm_instances: HashMap<usize, InnerPVM>,
    pub(crate) exported_segments: Vec<Octets>,
    pub(crate) next_instance_id: usize, // PVM instance ID to be assigned for the next instance
}

impl Default for RefinementContext {
    fn default() -> Self {
        Self {
            pvm_instances: HashMap::new(),
            exported_segments: Vec::new(),
            next_instance_id: 0,
        }
    }
}

impl RefinementContext {
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
