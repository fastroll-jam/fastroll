use crate::{
    codec::encode_length_discriminated_field,
    common::{Hash32, Octets},
    state::GlobalState,
};
use parity_scale_codec::Encode;
use std::collections::HashMap;

// State Serialization

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

fn construct_key_with_service_and_hash(s: u32, h: &Hash32) -> [u8; 32] {
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
pub(crate) fn serialize_state(state: &GlobalState) -> HashMap<Hash32, Octets> {
    let mut map = HashMap::new();

    map.insert(construct_key(1), state.authorization_pool.encode()); // alpha
    map.insert(construct_key(2), state.authorization_queue.encode()); // phi
    let mut encoded_block_history = vec![];
    encode_length_discriminated_field(&state.block_history, &mut encoded_block_history);
    map.insert(construct_key(3), encoded_block_history); // beta
    map.insert(construct_key(4), state.safrole_state.encode()); // gamma
    map.insert(construct_key(5), state.verdicts.encode()); // psi
    map.insert(construct_key(6), state.entropy_accumulator.encode()); // eta
    map.insert(construct_key(7), state.staging_validator_set.encode()); // iota
    map.insert(construct_key(8), state.active_validator_set.encode()); // kappa
    map.insert(construct_key(9), state.past_validator_set.encode()); // lambda
    map.insert(construct_key(10), state.pending_reports.encode()); // rho
    map.insert(construct_key(11), state.recent_timeslot.encode()); // tau
    map.insert(construct_key(12), state.privileged_services.encode()); // chi
    map.insert(construct_key(13), state.validator_statistics.encode()); // pi

    // service state
    for (service, account) in &state.service_accounts {
        map.insert(
            construct_key_with_service(255u8, *service),
            (
                account.code_hash,                    // Hash32
                account.balance,                      // u64
                account.gas_limit_accumulate,         // u64
                account.gas_limit_on_transfer,        // u64
                account.get_total_octets_footprint(), // u64
                account.get_item_counts_footprint(),  // u32
            )
                .encode(),
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
            encode_length_discriminated_field(lookup_value, &mut encoded_lookup_value);

            map.insert(
                construct_key_with_service_and_data(*service, lookup_key.encode()), // FIXME: with exact encoding rule for the `h`
                encoded_lookup_value,
            );
        }
    }

    map
}
