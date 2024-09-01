use crate::state::timeslot::Timeslot;
use jam_common::{AccountAddress, Hash32, Octets, TokenBalance, UnsignedGas};
use std::collections::BTreeMap;

#[derive(Default, Clone)]
pub struct ServiceAccounts(pub BTreeMap<AccountAddress, ServiceAccountState>);

#[derive(Clone)]
pub struct ServiceAccountState {
    pub storage: BTreeMap<Hash32, Octets>,               // s
    pub preimages: BTreeMap<Hash32, Octets>,             // p
    pub lookups: BTreeMap<(Hash32, u32), Vec<Timeslot>>, // l; Vec<u32> length up to 3
    pub code_hash: Hash32,                               // c
    pub balance: TokenBalance,                           // b
    pub gas_limit_accumulate: UnsignedGas,               // g
    pub gas_limit_on_transfer: UnsignedGas,              // m
}

impl ServiceAccounts {
    fn contains_key(&self, address: &AccountAddress) -> bool {
        self.0.contains_key(address)
    }

    pub fn check(&self, address: AccountAddress) -> AccountAddress {
        let mut check_address = address;
        loop {
            if !self.contains_key(&check_address) {
                return check_address;
            }

            check_address = ((check_address as u64 - (1 << 8) + 1) % ((1 << 32) - (1 << 9))
                + (1 << 8)) as AccountAddress;
        }
    }
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

    pub fn get_code(&self) -> Option<&Octets> {
        self.preimages.get(&self.code_hash)
    }
}
