use crate::{
    common::{Hash32, Octets},
    extrinsics::components::disputes::{Culprit, Fault, Verdict},
    state::components::timeslot::Timeslot,
};
use lazy_static::lazy_static;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum DisputesEntryType {
    Verdict(Verdict),
    Culprit(Culprit),
    Fault(Fault),
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum ExtrinsicType {
    Ticket,
    Guarantee,
    Assurance,
    PreimageLookup,
    Disputes,
}

const EXTRINSICS_POOL_MAX_SIZE: usize = 1000; // TODO: config
lazy_static! {
    pub static ref EXTRINSICS_POOL: RwLock<ExtrinsicsPool> =
        RwLock::new(ExtrinsicsPool::new(EXTRINSICS_POOL_MAX_SIZE));
}

// TODO: add Extrinsic Deserializer
// Extrinsics entry stored to the main `ExtrinsicsPool` in-memory pool
#[derive(Clone)]
pub struct ExtrinsicEntry {
    pub hash: Hash32,
    pub data: Octets, // serialized extrinsic data
    pub extrinsic_type: ExtrinsicType,
    pub timeslot: Timeslot,
    pub timestamp: u32, // optional?
}

pub struct ExtrinsicsPool {
    // Main storage
    extrinsics: Arc<RwLock<HashMap<Hash32, ExtrinsicEntry>>>,

    // Index for type and timeslot lookups
    type_timeslot_index: Arc<RwLock<BTreeMap<(ExtrinsicType, Timeslot), Vec<Hash32>>>>,

    max_size: usize,
}

impl ExtrinsicsPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            extrinsics: Arc::new(RwLock::new(HashMap::new())),
            type_timeslot_index: Arc::new(RwLock::new(BTreeMap::new())),
            max_size,
        }
    }

    // TODO: error handling
    // Write extrinsic entry to the pools
    pub fn add_extrinsic(&self, entry: ExtrinsicEntry) -> Result<(), String> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        if extrinsics.len() >= self.max_size {
            return Err("ExtrinsicsPool is full".to_string());
        }

        // Add to the main storage
        extrinsics.insert(entry.hash, entry.clone());

        // Add to the type-timeslot lookup index
        type_timeslot_index
            .entry((entry.extrinsic_type.clone(), entry.timeslot))
            .or_default()
            .push(entry.hash);

        Ok(())
    }

    // Read extrinsic entry from the pools
    pub fn get_extrinsics_by_type_and_timeslot(
        &self,
        extrinsic_type: ExtrinsicType,
        timeslot: Timeslot,
    ) -> Vec<ExtrinsicEntry> {
        let type_timeslot_index = self.type_timeslot_index.read().unwrap();
        let extrinsics = self.extrinsics.read().unwrap();

        type_timeslot_index
            .get(&(extrinsic_type, timeslot))
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|hash| extrinsics.get(hash).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    // Delete extrinsic entry from the pools
    pub fn remove_extrinsic(&self, hash: &Hash32) -> Option<ExtrinsicEntry> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        extrinsics.remove(hash).inspect(|extrinsic| {
            if let Some(hashes) =
                type_timeslot_index.get_mut(&(extrinsic.extrinsic_type.clone(), extrinsic.timeslot))
            {
                // Delete the hash entry being removed from the main storage
                hashes.retain(|&h| h != *hash);
                if hashes.is_empty() {
                    type_timeslot_index
                        .remove(&(extrinsic.extrinsic_type.clone(), extrinsic.timeslot));
                }
            }
        })
    }
}
