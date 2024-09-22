use crate::{
    global_state::GlobalStateError,
    trie::{
        merkle_trie::retrieve,
        serialization::{
            construct_key, construct_key_with_service_and_data,
            construct_key_with_service_and_hash, M,
        },
        utils::{bytes_to_lsb_bits, MerklizationError},
    },
};
use rjam_codec::{JamDecode, JamEncode};
use rjam_common::{Hash32, Octets};
use rjam_db::manager::GLOBAL_KVDB_MANAGER;
use rjam_types::state::{
    authorizer::{AuthorizerPool, AuthorizerQueue},
    disputes::DisputesState,
    entropy::EntropyAccumulator,
    histories::BlockHistories,
    privileged::PrivilegedServices,
    reports::PendingReports,
    safrole::SafroleState,
    statistics::ValidatorStats,
    timeslot::Timeslot,
    validators::{ActiveValidatorSet, PastValidatorSet, StagingValidatorSet},
};

fn get_current_root_hash() -> Hash32 {
    todo!() // move to `block/header.rs`
}

#[derive(Default)]
pub struct StateRetriever;

impl StateRetriever {
    pub fn new() -> Self {
        StateRetriever
    }

    // Getter functions to retrieve current state of each state component
    fn retrieve_state(&self, merkle_path_hash: Hash32) -> Result<Octets, MerklizationError> {
        let db_manager = GLOBAL_KVDB_MANAGER.lock().unwrap();
        let merkle_path = bytes_to_lsb_bits(merkle_path_hash.to_vec());
        let root_hash = get_current_root_hash();
        retrieve(&db_manager, root_hash, merkle_path)
    }

    pub fn get_authorizer_pool(&self) -> Result<AuthorizerPool, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Alpha))?;
        Ok(AuthorizerPool::decode(&mut serialized.as_slice())?)
    }

    pub fn get_authorizer_queue(&self) -> Result<AuthorizerQueue, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Phi))?;
        Ok(AuthorizerQueue::decode(&mut serialized.as_slice())?)
    }

    pub fn get_block_histories(&self) -> Result<BlockHistories, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Beta))?;
        Ok(BlockHistories::decode(&mut serialized.as_slice())?)
    }

    pub fn get_safrole_state(&self) -> Result<SafroleState, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Gamma))?;
        Ok(SafroleState::decode(&mut serialized.as_slice())?)
    }

    pub fn get_disputes(&self) -> Result<DisputesState, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Psi))?;
        Ok(DisputesState::decode(&mut serialized.as_slice())?)
    }

    pub fn get_entropy_accumulator(&self) -> Result<EntropyAccumulator, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Eta))?;
        Ok(EntropyAccumulator::decode(&mut serialized.as_slice())?)
    }

    pub fn get_staging_validator_set(&self) -> Result<StagingValidatorSet, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Iota))?;
        Ok(StagingValidatorSet::decode(&mut serialized.as_slice())?)
    }

    pub fn get_active_validator_set(&self) -> Result<ActiveValidatorSet, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Kappa))?;
        Ok(ActiveValidatorSet::decode(&mut serialized.as_slice())?)
    }

    pub fn get_past_validator_set(&self) -> Result<PastValidatorSet, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Lambda))?;
        Ok(PastValidatorSet::decode(&mut serialized.as_slice())?)
    }

    pub fn get_pending_reports(&self) -> Result<PendingReports, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Rho))?;
        Ok(PendingReports::decode(&mut serialized.as_slice())?)
    }

    pub fn get_recent_timeslot(&self) -> Result<Timeslot, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Tau))?;
        Ok(Timeslot::decode(&mut serialized.as_slice())?)
    }

    pub fn get_privileged_services(&self) -> Result<PrivilegedServices, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Chi))?;
        Ok(PrivilegedServices::decode(&mut serialized.as_slice())?)
    }

    pub fn get_validator_statistics(&self) -> Result<ValidatorStats, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key(M::Pi))?;
        Ok(ValidatorStats::decode(&mut serialized.as_slice())?)
    }

    pub fn get_service_storage_data(
        &self,
        service_idx: u32,
        storage_key: &Hash32,
    ) -> Result<Octets, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key_with_service_and_hash(
            service_idx,
            storage_key,
        ))?;
        Ok(Octets::decode(&mut serialized.as_slice())?)
    }

    pub fn get_service_preimage(
        &self,
        service_idx: u32,
        preimage_key: &Hash32,
    ) -> Result<Octets, GlobalStateError> {
        let serialized = self.retrieve_state(construct_key_with_service_and_hash(
            service_idx,
            preimage_key,
        ))?;
        Ok(Octets::decode(&mut serialized.as_slice())?)
    }

    pub fn get_service_lookup(
        &self,
        service_idx: u32,
        lookup_key: &(Hash32, u32),
    ) -> Result<Vec<Timeslot>, GlobalStateError> {
        let encoded_lookup_key = lookup_key.encode()?;
        let serialized = self.retrieve_state(construct_key_with_service_and_data(
            service_idx,
            &encoded_lookup_key,
        ))?;
        Ok(Vec::<Timeslot>::decode(&mut serialized.as_slice())?)
    }
}
