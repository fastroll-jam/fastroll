use crate::inner_vm::InnerPVM;
use rjam_codec::{JamDecodeFixed, JamEncode};
use rjam_common::{Address, DeferredTransfer, Hash32};
use rjam_crypto::utils::blake2b_256;
use rjam_pvm_core::types::{common::ExportDataSegment, error::PVMError};
use rjam_state::StateManager;
use rjam_types::state::timeslot::Timeslot;
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

#[derive(Default, Clone)]
pub struct AccumulateContext {
    pub deferred_transfers: Vec<DeferredTransfer>,
    next_new_account_address: Address,
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

    fn initialize_new_account_address(
        state_manager: &StateManager,
        target_address: Address,
        entropy: Hash32,
        timeslot: &Timeslot,
    ) -> Result<Address, PVMError> {
        // TODO: confirm how to deal with hash of a tuple; H(address, entropy, timestamp); check GP appendix B.4.
        let mut buf = vec![];
        target_address.encode_to(&mut buf)?;
        entropy.encode_to(&mut buf)?;
        timeslot.0.encode_to(&mut buf)?;

        let source_hash = blake2b_256(&buf[..])?;
        let initial_check_address = (u32::decode_fixed(&mut &source_hash[..], 4)? as u64
            & ((1 << 32) - (1 << 9)) + (1 << 8)) as Address;
        let new_account_address = state_manager.check(initial_check_address)?;

        Ok(new_account_address)
    }

    pub fn get_next_new_account_address(&self) -> Address {
        self.next_new_account_address
    }

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
