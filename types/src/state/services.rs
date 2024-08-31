use crate::state::timeslot::Timeslot;
use jam_common::{Hash32, Octets, UnsignedGas};
use std::collections::BTreeMap;

pub struct ServiceAccounts(pub BTreeMap<u32, ServiceAccountState>);

pub struct ServiceAccountState {
    pub storage: BTreeMap<Hash32, Octets>,               // s
    pub preimages: BTreeMap<Hash32, Octets>,             // p
    pub lookups: BTreeMap<(Hash32, u32), Vec<Timeslot>>, // l; Vec<u32> length up to 3
    pub code_hash: Hash32,                               // c
    pub balance: u64,                                    // b
    pub gas_limit_accumulate: UnsignedGas,               // g
    pub gas_limit_on_transfer: UnsignedGas,              // m
}

impl ServiceAccountState {
    // get the number of items in the storage, which is represented as `i` of account state.
    pub fn get_item_counts_footprint(&self) -> u32 {
        todo!()
    }

    // get the number of total octets used in the storage, which is represented as `l` of account state.
    pub fn get_total_octets_footprint(&self) -> u64 {
        todo!()
    }
}
