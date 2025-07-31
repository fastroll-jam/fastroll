use crate::context::{AccumulateHostContext, AccumulateHostContextPair};
use async_trait::async_trait;
use fr_common::{Hash32, LookupsKey, Octets, ServiceId, SignedGas};
use fr_pvm_core::state::{
    memory::{AccessType, Memory},
    register::Register,
    vm_state::VMState,
};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT},
};
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    provider::HostStateProvider,
    types::{
        privileges::PrivilegedServices, AccountLookupsEntry, AccountMetadata,
        AccountPreimagesEntry, AccountStorageEntry,
    },
};
use std::{collections::HashMap, error::Error, ops::Range};

#[allow(dead_code)]
struct MockAccountState {
    metadata: AccountMetadata,
    storage: HashMap<Octets, AccountStorageEntry>,
    preimages: HashMap<Hash32, AccountPreimagesEntry>,
    lookups: HashMap<LookupsKey, AccountLookupsEntry>,
}

#[allow(dead_code)]
pub(crate) struct MockStateManager {
    accounts: HashMap<ServiceId, MockAccountState>,
    privileges: PrivilegedServices,
}

#[async_trait]
impl HostStateProvider for MockStateManager {
    async fn get_privileged_services(&self) -> Result<PrivilegedServices, StateManagerError> {
        Ok(self.privileges.clone())
    }

    async fn account_exists(&self, service_id: ServiceId) -> Result<bool, StateManagerError> {
        Ok(self.accounts.contains_key(&service_id))
    }

    async fn check(&self, service_id: ServiceId) -> Result<ServiceId, StateManagerError> {
        StateManager::check_impl(service_id, |id| self.account_exists(id)).await
    }

    async fn get_account_metadata(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountMetadata>, StateManagerError> {
        Ok(self
            .accounts
            .get(&service_id)
            .map(|account| account.metadata.clone()))
    }

    async fn get_account_storage_entry(
        &self,
        service_id: ServiceId,
        storage_key: &Octets,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError> {
        Ok(self
            .accounts
            .get(&service_id)
            .and_then(|account| account.storage.get(storage_key).cloned()))
    }

    async fn get_account_preimages_entry(
        &self,
        service_id: ServiceId,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError> {
        Ok(self
            .accounts
            .get(&service_id)
            .and_then(|account| account.preimages.get(preimages_key).cloned()))
    }

    async fn get_account_lookups_entry(
        &self,
        service_id: ServiceId,
        lookups_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError> {
        Ok(self
            .accounts
            .get(&service_id)
            .and_then(|account| account.lookups.get(lookups_key).cloned()))
    }
}

pub(crate) fn mock_empty_vm_state(gas_counter: SignedGas) -> VMState {
    VMState {
        regs: [Register::default(); REGISTERS_COUNT],
        memory: Memory::default(),
        pc: 0,
        gas_counter,
    }
}

pub(crate) fn mock_vm_state(
    gas_counter: SignedGas,
    pc: RegValue,
    regs: [Register; REGISTERS_COUNT],
    memory: Memory,
) -> VMState {
    VMState {
        regs,
        memory,
        pc,
        gas_counter,
    }
}

pub(crate) fn mock_accumulate_host_context(
    accumulate_host: ServiceId,
) -> AccumulateHostContextPair {
    let context = AccumulateHostContext {
        accumulate_host,
        ..Default::default()
    };
    AccumulateHostContextPair {
        x: Box::new(context.clone()),
        y: Box::new(context),
    }
}

pub(crate) fn mock_memory(
    readable_range: Range<MemAddress>,
    writable_range: Range<MemAddress>,
) -> Result<Memory, Box<dyn Error>> {
    let mut mem = Memory::new(MEMORY_SIZE, PAGE_SIZE);
    mem.set_address_range_access(readable_range, AccessType::ReadOnly)?;
    mem.set_address_range_access(writable_range, AccessType::ReadWrite)?;
    Ok(mem)
}
