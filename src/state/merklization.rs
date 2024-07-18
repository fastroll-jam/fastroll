use crate::{
    common::{Hash32, Octets},
    state::GlobalState,
};
use parity_scale_codec::Encode;
use std::collections::HashMap;

// SCALE encoder alias
fn se<T: Encode>(value: &T) -> Vec<u8> {
    value.encode()
}

fn construct_key(i: u8) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i;
    key
}

fn construct_key_with_service(i: u8, s: u32) -> Hash32 {
    let mut key = [0u8; 32];
    key[0] = i;
    key[1..5].copy_from_slice(&s.to_be_bytes());
    key
}

fn construct_key_with_service_and_data(s: u32, h: Octets) -> [u8; 32] {
    let mut key = [0u8; 32];

    let s_bytes = s.to_be_bytes();
    let mut h_bytes: Vec<u8> = h.clone();
    h_bytes.truncate(28);

    for i in 0..4 {
        key[i * 2] = s_bytes[i]; // 0, 2, 4, 6
        key[i * 2 + 1] = h_bytes[i]; // 1, 3, 5, 7
    }

    key[8..32].copy_from_slice(&h_bytes[4..28]);

    key
}

// Mapping from key to serialized GlobalState
fn serialize_state(state: &GlobalState) -> HashMap<Hash32, Octets> {
    let mut map = HashMap::new();

    map.insert(construct_key(1), se(&state.authorization_pool)); // alpha
    map.insert(construct_key(2), se(&state.authorization_queue)); // phi
    map.insert(construct_key(3), se(&state.block_history)); // beta
    map.insert(construct_key(4), se(&state.safrole_state)); // gamma
    map.insert(construct_key(5), se(&state.verdicts)); // psi
    map.insert(construct_key(6), se(&state.entropy_accumulator)); // eta
    map.insert(construct_key(7), se(&state.staging_validator_set)); // iota
    map.insert(construct_key(8), se(&state.active_validator_set)); // kappa
    map.insert(construct_key(9), se(&state.past_validator_set)); // lambda
    map.insert(construct_key(10), se(&state.pending_reports)); // rho
    map.insert(construct_key(11), se(&state.recent_timeslot)); // tau
    map.insert(construct_key(12), se(&state.privileged_services)); // chi
    map.insert(construct_key(13), se(&state.validator_statistics)); // pi


    map
}
