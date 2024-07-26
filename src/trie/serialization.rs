use crate::{
    codec::JamEncode,
    common::{Hash32, Octets},
    state::global_state::{GlobalState, GlobalStateError},
};
use std::collections::HashMap;
// State Serialization

// Index of each state component used for Merkle path construction
pub(crate) enum M {
    Alpha = 1,
    Phi = 2,
    Beta = 3,
    Gamma = 4,
    Psi = 5,
    Eta = 6,
    Iota = 7,
    Kappa = 8,
    Lambda = 9,
    Rho = 10,
    Tau = 11,
    Chi = 12,
    Pi = 13,
    Sigma = 255,
}

impl From<M> for u8 {
    fn from(val: M) -> Self {
        val as u8
    }
}

pub(crate) fn construct_key<T: Into<u8>>(i: T) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i.into();
    key
}

pub(crate) fn construct_key_with_service<T: Into<u8>>(i: T, s: u32) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i.into();
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

pub(crate) fn construct_key_with_service_and_data(s: u32, h: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];

    let s_bytes = s.to_be_bytes();
    let h_len = h.len().min(28);

    for i in 0..4 {
        key[i * 2] = s_bytes[i];
        if i < h_len {
            key[i * 2 + 1] = h[i];
        }
    }

    if h_len > 4 {
        key[8..8 + h_len - 4].copy_from_slice(&h[4..h_len]);
    }

    key
}

pub(crate) fn construct_key_with_service_and_hash(s: u32, h: &Hash32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let s_bytes = s.to_be_bytes();
    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h[i]; // 1, 3, 5, 7
    }
    key[8..32].copy_from_slice(&h[4..28]);

    key
}

// Mapping from key to serialized GlobalState
pub(crate) fn serialize_state(
    state: &GlobalState,
) -> Result<HashMap<Hash32, Octets>, GlobalStateError> {
    let mut map = HashMap::new();

    map.insert(construct_key(M::Alpha), state.authorizer_pool.encode()?); // alpha
    map.insert(construct_key(M::Phi), state.authorizer_queue.encode()?); // phi
    map.insert(construct_key(M::Beta), state.block_histories.encode()?); // beta
    map.insert(construct_key(M::Gamma), state.safrole_state.encode()?); // gamma
    map.insert(construct_key(M::Psi), state.disputes.encode()?); // psi
    map.insert(construct_key(M::Eta), state.entropy_accumulator.encode()?); // eta
    map.insert(
        construct_key(M::Iota),
        state.staging_validator_set.encode()?,
    ); // iota
    map.insert(
        construct_key(M::Kappa),
        state.active_validator_set.encode()?,
    ); // kappa
    map.insert(construct_key(M::Lambda), state.past_validator_set.encode()?); // lambda
    map.insert(construct_key(M::Rho), state.pending_reports.encode()?); // rho
    map.insert(construct_key(M::Tau), state.recent_timeslot.encode()?); // tau
    map.insert(construct_key(M::Chi), state.privileged_services.encode()?); // chi
    map.insert(construct_key(M::Pi), state.validator_statistics.encode()?); // pi

    // service state
    for (service, account) in &state.service_accounts.0 {
        map.insert(
            construct_key_with_service(M::Sigma, *service),
            (
                account.code_hash,                    // Hash32
                account.balance,                      // u64
                account.gas_limit_accumulate,         // u64
                account.gas_limit_on_transfer,        // u64
                account.get_total_octets_footprint(), // u64
                account.get_item_counts_footprint(),  // u32
            )
                .encode()?,
        );

        for (storage_key, storage_value) in &account.storage {
            map.insert(
                construct_key_with_service_and_hash(*service, storage_key),
                storage_value.clone(),
            );
        }

        for (preimage_key, preimage_value) in &account.preimages {
            map.insert(
                construct_key_with_service_and_hash(*service, preimage_key),
                preimage_value.clone(),
            );
        }

        // lookup_value is a sequence of timeslots with length up to 3 which describes the historical status of preimages.
        for (lookup_key, lookup_value) in &account.lookups {
            let mut encoded_lookup_value = vec![];
            lookup_value.encode_to(&mut encoded_lookup_value)?;

            map.insert(
                construct_key_with_service_and_data(*service, &lookup_key.encode()?), // FIXME: with exact encoding rule for the `h`
                encoded_lookup_value,
            );
        }
    }

    Ok(map)
}
