#![allow(dead_code)]
use async_trait::async_trait;
use fr_common::{Hash32, LookupsKey, Octets, ServiceId, SignedGas};
use fr_pvm_core::state::{
    memory::{AccessType, Memory},
    register::Register,
    vm_state::VMState,
};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::REGISTERS_COUNT,
};
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    provider::HostStateProvider,
    types::{
        privileges::PrivilegedServices, AccountLookupsEntry, AccountMetadata,
        AccountPreimagesEntry, AccountStorageEntry, Timeslot,
    },
};
use std::{collections::HashMap, error::Error, ops::Range};

#[derive(Default)]
struct MockAccountState {
    metadata: AccountMetadata,
    storage: HashMap<Octets, AccountStorageEntry>,
    preimages: HashMap<Hash32, AccountPreimagesEntry>,
    lookups: HashMap<LookupsKey, AccountLookupsEntry>,
}

impl MockAccountState {
    fn new_with_account_metadata(metadata: AccountMetadata) -> Self {
        Self {
            metadata,
            ..Default::default()
        }
    }
}

#[derive(Default)]
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

    async fn lookup_historical_preimage(
        &self,
        _service_id: ServiceId,
        _reference_timeslot: &Timeslot,
        _preimage_hash: &Hash32,
    ) -> Result<Option<Vec<u8>>, StateManagerError> {
        unimplemented!()
    }
}

impl MockStateManager {
    pub(crate) fn builder() -> Self {
        Self::default()
    }

    pub(crate) fn with_privileged_services(mut self, privileges: PrivilegedServices) -> Self {
        self.privileges = privileges;
        self
    }

    pub(crate) fn with_empty_account(mut self, service_id: ServiceId) -> Self {
        self.accounts
            .insert(service_id, MockAccountState::default());
        self
    }

    pub(crate) fn with_account(mut self, service_id: ServiceId, metadata: AccountMetadata) -> Self {
        self.accounts.insert(
            service_id,
            MockAccountState::new_with_account_metadata(metadata),
        );
        self
    }

    pub(crate) fn with_storage_entry(
        mut self,
        service_id: ServiceId,
        key: Octets,
        entry: AccountStorageEntry,
    ) -> Self {
        self.accounts
            .get_mut(&service_id)
            .and_then(|account| account.storage.insert(key, entry));
        self
    }

    pub(crate) fn with_preimages_entry(
        mut self,
        service_id: ServiceId,
        key: Hash32,
        entry: AccountPreimagesEntry,
    ) -> Self {
        self.accounts
            .get_mut(&service_id)
            .and_then(|account| account.preimages.insert(key, entry));
        self
    }

    pub(crate) fn with_lookups_entry(
        mut self,
        service_id: ServiceId,
        key: LookupsKey,
        entry: AccountLookupsEntry,
    ) -> Self {
        self.accounts
            .get_mut(&service_id)
            .and_then(|account| account.lookups.insert(key, entry));
        self
    }
}

#[derive(Default)]
pub(crate) struct VMStateBuilder {
    pub regs: [Register; REGISTERS_COUNT],
    pub memory: Memory,
    pub pc: RegValue,
    pub gas_counter: SignedGas,
}

impl VMStateBuilder {
    pub(crate) fn builder() -> Self {
        Self::default()
    }

    pub(crate) fn with_reg(mut self, reg_idx: usize, reg_val: impl Into<RegValue>) -> Self {
        if reg_idx >= REGISTERS_COUNT {
            panic!("Register index out of bounds: {reg_idx:?}");
        }
        self.regs[reg_idx].value = reg_val.into();
        self
    }

    pub(crate) fn with_pc(mut self, pc: RegValue) -> Self {
        self.pc = pc;
        self
    }

    pub(crate) fn with_gas_counter(mut self, gas_counter: SignedGas) -> Self {
        self.gas_counter = gas_counter;
        self
    }

    pub(crate) fn with_mem_readable_range(
        mut self,
        range: Range<MemAddress>,
    ) -> Result<Self, Box<dyn Error>> {
        self.memory
            .set_address_range_access(range, AccessType::ReadOnly)?;
        Ok(self)
    }

    pub(crate) fn with_mem_writable_range(
        mut self,
        range: Range<MemAddress>,
    ) -> Result<Self, Box<dyn Error>> {
        self.memory
            .set_address_range_access(range, AccessType::ReadWrite)?;
        Ok(self)
    }

    pub(crate) fn build(self) -> VMState {
        VMState {
            regs: self.regs,
            memory: self.memory,
            pc: self.pc,
            gas_counter: self.gas_counter,
        }
    }
}
