use crate::state::timeslot::Timeslot;
use jam_common::{AccountAddress, Hash32, Octets, TokenBalance, UnsignedGas};
use std::collections::BTreeMap;

pub const B_S: TokenBalance = 100; // The basic minimum balance which all services require
pub const B_I: TokenBalance = 10; // The additional minimum balance required per item of elective service state
pub const B_L: TokenBalance = 1; // The additional minimum balance required per octet of elective service state

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

    pub fn get_account(&self, address: &AccountAddress) -> Option<&ServiceAccountState> {
        self.0.get(address)
    }
}

impl ServiceAccountState {
    // Historical lookup function for checking availability of the lookup hash at a given timeslot.
    // Returns preimage blob if available.

    pub fn lookup_history(&self, timeslot: &Timeslot, lookup_hash: Hash32) -> Option<Octets> {
        let preimage = self.preimages.get(&lookup_hash)?;
        let key = (lookup_hash, preimage.len() as u32);
        let timeslots = self.lookups.get(&key)?;

        let valid = match timeslots.as_slice() {
            [] => false,
            [first] => first <= timeslot,
            [first, second] => first <= timeslot && timeslot < second,
            [first, second, third] => (first <= timeslot && timeslot < second) || third <= timeslot,
            _ => false,
        };

        if valid {
            Some(preimage.clone())
        } else {
            None
        }
    }

    // Get the number of items in the storage (i)
    pub fn get_item_counts_footprint(&self) -> u32 {
        (2 * self.lookups.len() + self.storage.len()) as u32
    }

    // Get the number of total octets used in the storage (l)
    pub fn get_total_octets_footprint(&self) -> u64 {
        let lookup_octets: u64 = self.lookups.iter().map(|((_, z), _)| 81 + *z as u64).sum();
        let storage_octets: u64 = self.storage.values().map(|x| 32 + x.len() as u64).sum();

        lookup_octets + storage_octets
    }

    // Get the account threshold balance (t)
    pub fn get_threshold_balance(&self) -> TokenBalance {
        let i = self.get_item_counts_footprint() as TokenBalance;
        let l = self.get_total_octets_footprint() as TokenBalance;

        B_S + B_I * i + B_L * l
    }

    pub fn get_code(&self) -> Option<&Octets> {
        self.preimages.get(&self.code_hash)
    }
}
