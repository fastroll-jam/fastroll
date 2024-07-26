use crate::{
    common::{Hash32, Octets, UnsignedGas},
    state::components::timeslot::Timeslot,
};
use std::collections::BTreeMap;

pub(crate) struct ServiceAccounts(pub(crate) BTreeMap<u32, ServiceAccountState>);

pub(crate) struct ServiceAccountState {
    pub(crate) storage: BTreeMap<Hash32, Octets>,   // s
    pub(crate) preimages: BTreeMap<Hash32, Octets>, // p
    pub(crate) lookups: BTreeMap<(Hash32, u32), Vec<Timeslot>>, // l; Vec<u32> length up to 3
    pub(crate) code_hash: Hash32,                   // c
    pub(crate) balance: u64,                        // b
    pub(crate) gas_limit_accumulate: UnsignedGas,   // g
    pub(crate) gas_limit_on_transfer: UnsignedGas,  // m
}

impl ServiceAccountState {
    // get the number of items in the storage, which is represented as `i` of account state.
    pub(crate) fn get_item_counts_footprint(&self) -> u32 {
        todo!()
    }

    // get the number of total octets used in the storage, which is represented as `l` of account state.
    pub(crate) fn get_total_octets_footprint(&self) -> u64 {
        todo!()
    }
}
