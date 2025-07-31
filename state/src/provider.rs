use crate::{
    error::StateManagerError,
    types::{
        privileges::PrivilegedServices, AccountLookupsEntry, AccountMetadata,
        AccountPreimagesEntry, AccountStorageEntry, Timeslot,
    },
};
use async_trait::async_trait;
use fr_common::{Hash32, LookupsKey, Octets, ServiceId};

/// State provider defining the interface for host state access in the PVM.
///
/// This abstraction allows for different implementations including
/// state management, test mocks, etc.
#[async_trait]
pub trait HostStateProvider {
    /// Get privileged services info.
    async fn get_privileged_services(&self) -> Result<PrivilegedServices, StateManagerError>;

    /// Checks if a service account with the given service id exists in the global state.
    async fn account_exists(&self, service_id: ServiceId) -> Result<bool, StateManagerError>;

    /// Ensures a unique service id by checking if the given id exists in global state.
    /// If it exists, rotates through alternative ids using an internal rotation mechanism
    /// until finding one that doesn't collide with existing service accounts.
    async fn check(&self, service_id: ServiceId) -> Result<ServiceId, StateManagerError>;

    /// Get account metadata of the given service id.
    async fn get_account_metadata(
        &self,
        service_id: ServiceId,
    ) -> Result<Option<AccountMetadata>, StateManagerError>;

    /// Get account storage entry with the given service id and storage key.
    async fn get_account_storage_entry(
        &self,
        service_id: ServiceId,
        storage_key: &Octets,
    ) -> Result<Option<AccountStorageEntry>, StateManagerError>;

    /// Get account preimages entry with the given service id and storage key.
    async fn get_account_preimages_entry(
        &self,
        service_id: ServiceId,
        preimages_key: &Hash32,
    ) -> Result<Option<AccountPreimagesEntry>, StateManagerError>;

    /// Get account lookups entry with the given service id and storage key.
    async fn get_account_lookups_entry(
        &self,
        service_id: ServiceId,
        lookups_key: &LookupsKey,
    ) -> Result<Option<AccountLookupsEntry>, StateManagerError>;

    async fn lookup_historical_preimage(
        &self,
        service_id: ServiceId,
        reference_timeslot: &Timeslot,
        preimage_hash: &Hash32,
    ) -> Result<Option<Vec<u8>>, StateManagerError>;
}
