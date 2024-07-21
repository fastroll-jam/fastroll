use crate::{
    common::{Hash32, Octets},
    db::manager::GLOBAL_KVDB_MANAGER,
    trie::{
        merkle_trie::retrieve,
        serialization::{
            construct_key, construct_key_with_service_and_data,
            construct_key_with_service_and_hash, M,
        },
        utils::bytes_to_lsb_bits,
    },
};
use parity_scale_codec::Encode;

fn get_current_root_hash() -> Hash32 {
    todo!() // move to `block/header.rs`
}

pub struct StateRetriever;

impl StateRetriever {
    pub(crate) fn new() -> Self {
        StateRetriever
    }

    // Getter functions to retrieve current state of each state component
    // FIXME: apply decoders so that each getter function can return the Rust type representation
    fn retrieve_state(&self, merkle_path_hash: Hash32) -> Octets {
        let db_manager = GLOBAL_KVDB_MANAGER.lock().unwrap();
        let merkle_path = bytes_to_lsb_bits(merkle_path_hash.to_vec());
        let root_hash = get_current_root_hash();
        retrieve(&db_manager, root_hash, merkle_path)
            .expect("Failed to fetch current state component")
    }

    pub fn get_authorization_pool(&self) -> Octets {
        self.retrieve_state(construct_key(M::Alpha))
    }

    pub fn get_authorization_queue(&self) -> Octets {
        self.retrieve_state(construct_key(M::Phi))
    }

    pub fn get_block_history(&self) -> Octets {
        self.retrieve_state(construct_key(M::Beta))
    }

    pub fn get_safrole_state(&self) -> Octets {
        self.retrieve_state(construct_key(M::Gamma))
    }

    pub fn get_verdicts(&self) -> Octets {
        self.retrieve_state(construct_key(M::Psi))
    }

    pub fn get_entropy_accumulator(&self) -> Octets {
        self.retrieve_state(construct_key(M::Eta))
    }

    pub fn get_staging_validator_set(&self) -> Octets {
        self.retrieve_state(construct_key(M::Iota))
    }

    pub fn get_active_validator_set(&self) -> Octets {
        self.retrieve_state(construct_key(M::Kappa))
    }

    pub fn get_past_validator_set(&self) -> Octets {
        self.retrieve_state(construct_key(M::Lambda))
    }

    pub fn get_pending_reports(&self) -> Octets {
        self.retrieve_state(construct_key(M::Rho))
    }

    pub fn get_recent_timeslot(&self) -> Octets {
        self.retrieve_state(construct_key(M::Tau))
    }

    pub fn get_privileged_services(&self) -> Octets {
        self.retrieve_state(construct_key(M::Chi))
    }

    pub fn get_validator_statistics(&self) -> Octets {
        self.retrieve_state(construct_key(M::Pi))
    }

    pub fn get_service_storage(&self, service_idx: u32, storage_key: &Hash32) -> Octets {
        self.retrieve_state(construct_key_with_service_and_hash(
            service_idx,
            storage_key,
        ))
    }

    pub fn get_service_preimage(&self, service_idx: u32, preimage_key: &Hash32) -> Octets {
        self.retrieve_state(construct_key_with_service_and_hash(
            service_idx,
            preimage_key,
        ))
    }

    pub fn get_service_lookup(&self, service_idx: u32, lookup_key: &(Hash32, u32)) -> Octets {
        let encoded_lookup_key = lookup_key.encode();
        self.retrieve_state(construct_key_with_service_and_data(
            service_idx,
            &encoded_lookup_key,
        ))
    }
}
