#![allow(dead_code)]
use crate::context::{
    partial_state::AccumulatePartialState, AccumulateHostContext, AccumulateHostContextPair,
    InvocationContext, IsAuthorizedHostContext, RefineHostContext,
};
use async_trait::async_trait;
use fr_common::{EntropyHash, Hash32, LookupsKey, Octets, ServiceId, SignedGas, TimeslotIndex};
use fr_pvm_core::state::{
    memory::{AccessType, Memory},
    register::Register,
    vm_state::VMState,
};
use fr_pvm_types::{
    common::{MemAddress, RegValue},
    constants::{MEMORY_SIZE, PAGE_SIZE, REGISTERS_COUNT},
    invoke_args::AccumulateInvokeArgs,
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
use std::{collections::HashMap, error::Error, ops::Range, sync::Arc};

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
    mem_write_done: bool,
}

impl VMStateBuilder {
    pub(crate) fn builder() -> Self {
        Self {
            memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
            ..Default::default()
        }
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

    pub(crate) fn with_empty_mem(mut self) -> Self {
        self.mem_write_done = true;
        self
    }

    pub(crate) fn with_mem_data(
        mut self,
        start_address: impl Into<MemAddress>,
        bytes: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        let start_address = start_address.into();
        let range = start_address..start_address + bytes.len() as MemAddress;
        // Temporary write access for the data write
        self.memory
            .set_address_range_access(range.clone(), AccessType::ReadWrite)?;
        self.memory.write_bytes(start_address, bytes)?;
        self.memory
            .set_address_range_access(range, AccessType::Inaccessible)?;
        self.mem_write_done = true;
        Ok(self)
    }

    pub(crate) fn with_mem_readable_range(
        mut self,
        range: Range<MemAddress>,
    ) -> Result<Self, Box<dyn Error>> {
        if !self.mem_write_done {
            panic!("Mem data write should be done prior to setting access pattern")
        }
        self.memory
            .set_address_range_access(range, AccessType::ReadOnly)?;
        Ok(self)
    }

    pub(crate) fn with_mem_writable_range(
        mut self,
        range: Range<MemAddress>,
    ) -> Result<Self, Box<dyn Error>> {
        if !self.mem_write_done {
            panic!("Mem data write should be done prior to setting access pattern")
        }
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

#[allow(non_camel_case_types)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum InvocationContextBuilder {
    X_I(IsAuthorizedHostContext),
    X_R(RefineHostContext),
    X_A(AccumulateHostContextPair<MockStateManager>),
}

impl InvocationContextBuilder {
    pub(crate) fn refine_context_builder() -> Self {
        Self::X_R(RefineHostContext::default())
    }

    pub(crate) async fn accumulate_context_builder_with_default_entropy_and_timeslot(
        state_provider: Arc<MockStateManager>,
        accumulate_host: ServiceId,
    ) -> Result<Self, Box<dyn Error>> {
        Self::accumulate_context_builder(
            state_provider,
            accumulate_host,
            EntropyHash::default(),
            TimeslotIndex::default(),
        ).await
    }

    pub(crate) async fn accumulate_context_builder(
        state_provider: Arc<MockStateManager>,
        accumulate_host: ServiceId,
        curr_entropy: EntropyHash,
        curr_timeslot_index: TimeslotIndex,
    ) -> Result<Self, Box<dyn Error>> {
        let partial_state = AccumulatePartialState::default();
        let context = AccumulateHostContext::new(
            state_provider.clone(),
            partial_state,
            accumulate_host,
            curr_entropy,
            curr_timeslot_index,
            AccumulateInvokeArgs::default(),
        )
        .await?;
        Ok(Self::X_A(AccumulateHostContextPair {
            x: Box::new(context.clone()),
            y: Box::new(context),
        }))
    }

    pub(crate) fn build(self) -> InvocationContext<MockStateManager> {
        match self {
            Self::X_I(context) => InvocationContext::X_I(context),
            Self::X_R(context) => InvocationContext::X_R(context),
            Self::X_A(context) => InvocationContext::X_A(context),
        }
    }
}
