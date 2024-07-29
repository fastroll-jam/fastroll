use crate::{
    common::Hash32,
    extrinsics::components::{
        assurances::AssuranceExtrinsicEntry,
        disputes::{Culprit, Fault, Verdict},
        guarantees::GuaranteeExtrinsicEntry,
        preimages::PreimageLookupExtrinsicEntry,
        tickets::TicketExtrinsicEntry,
    },
    state::components::timeslot::Timeslot,
};
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
    Ticket(TicketExtrinsicEntry),
    Guarantee(GuaranteeExtrinsicEntry),
    Assurance(AssuranceExtrinsicEntry),
    PreimageLookup(PreimageLookupExtrinsicEntry),
    Disputes(DisputesEntryType),
}

// Extrinsics entry stored to the main `ExtrinsicPool` in-memory pool
#[derive(Clone)]
pub struct Extrinsic {
    hash: Hash32,
    data: Vec<u8>, // serialized extrinsic data
    extrinsic_type: ExtrinsicType,
    timeslot: Timeslot,
    timestamp: u32, // optional?
}

pub struct ExtrinsicPool {
    // Main storage
    extrinsics: Arc<RwLock<HashMap<Hash32, Extrinsic>>>,

    // Index for type and timeslot lookups
    type_timeslot_index: Arc<RwLock<BTreeMap<(ExtrinsicType, Timeslot), Vec<Hash32>>>>,

    max_size: usize,
}

impl ExtrinsicPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            extrinsics: Arc::new(RwLock::new(HashMap::new())),
            type_timeslot_index: Arc::new(RwLock::new(BTreeMap::new())),
            max_size,
        }
    }

    // TODO: error handling
    // Write extrinsic entry to the pools
    pub fn add_extrinsic(&self, extrinsic: Extrinsic) -> Result<(), String> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        if extrinsics.len() >= self.max_size {
            return Err("ExtrinsicPool is full".to_string());
        }

        // Add to the main storage
        extrinsics.insert(extrinsic.hash, extrinsic.clone());

        // Add to the type-timeslot lookup index
        type_timeslot_index
            .entry((extrinsic.extrinsic_type.clone(), extrinsic.timeslot))
            .or_insert_with(Vec::new)
            .push(extrinsic.hash);

        Ok(())
    }

    // Read extrinsic entry from the pools
    pub fn get_extrinsics_by_type_and_timeslot(
        &self,
        extrinsic_type: ExtrinsicType,
        timeslot: Timeslot,
    ) -> Vec<Extrinsic> {
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
            .unwrap_or_else(Vec::new)
    }

    // Delete extrinsic entry from the pools
    pub fn remove_extrinsic(&self, hash: &Hash32) -> Option<Extrinsic> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        extrinsics.remove(hash).map(|extrinsic| {
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
            extrinsic
        })
    }
}
