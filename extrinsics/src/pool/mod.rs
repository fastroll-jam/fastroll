use lazy_static::lazy_static;
use rjam_common::Hash32;
use rjam_types::extrinsics::disputes::{Culprit, Fault, Verdict};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};
use thiserror::Error;

type ExtrinsicsMap = Arc<RwLock<HashMap<Hash32, ExtrinsicEntry>>>;
type TypeTimeslotIndex = Arc<RwLock<BTreeMap<(ExtrinsicType, u32), Vec<Hash32>>>>; // u32 for timeslot index

#[derive(Debug, Error)]
pub enum ExtrinsicsPoolError {
    #[error("Extrinsics pool is full")]
    Full,
}

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
    Verdict,
    Culprit,
    Fault,
}

const EXTRINSICS_POOL_MAX_SIZE: usize = 1000; // TODO: config
lazy_static! {
    pub static ref EXTRINSICS_POOL: RwLock<ExtrinsicsPool> =
        RwLock::new(ExtrinsicsPool::new(EXTRINSICS_POOL_MAX_SIZE));
}

// Extrinsics entry stored to the main `ExtrinsicsPool` in-memory pool
#[derive(Clone)]
pub struct ExtrinsicEntry {
    pub hash: Hash32,
    pub data: Vec<u8>, // serialized extrinsic data
    pub extrinsic_type: ExtrinsicType,
    pub timeslot_index: u32,
}

/// Main in-memory data structure for storing unprocessed extrinsics
pub struct ExtrinsicsPool {
    /// Main storage
    extrinsics: ExtrinsicsMap,
    /// Index for type and timeslot lookups
    type_timeslot_index: TypeTimeslotIndex,
    /// Maximum size of the pool
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

    /// Adds an extrinsic entry to the in-memory pool
    pub fn add_extrinsic(&self, entry: ExtrinsicEntry) -> Result<(), ExtrinsicsPoolError> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        if extrinsics.len() >= self.max_size {
            return Err(ExtrinsicsPoolError::Full);
        }

        // Add to the main storage
        extrinsics.insert(entry.hash, entry.clone());

        // Add to the type-timeslot lookup index
        type_timeslot_index
            .entry((entry.extrinsic_type.clone(), entry.timeslot_index))
            .or_default()
            .push(entry.hash);

        Ok(())
    }

    /// Reads an extrinsic entry from the in-memory pool
    pub fn get_extrinsics_by_type_and_timeslot(
        &self,
        extrinsic_type: ExtrinsicType,
        timeslot_index: u32,
    ) -> Result<Vec<ExtrinsicEntry>, ExtrinsicsPoolError> {
        let type_timeslot_index = self.type_timeslot_index.read().unwrap();
        let extrinsics = self.extrinsics.read().unwrap();

        Ok(type_timeslot_index
            .get(&(extrinsic_type, timeslot_index))
            .map(|hashes| {
                hashes
                    .iter()
                    .filter_map(|hash| extrinsics.get(hash).cloned())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Deletes an extrinsic entry from the in-memory pool
    pub fn remove_extrinsic(
        &self,
        hash: &Hash32,
    ) -> Result<Option<ExtrinsicEntry>, ExtrinsicsPoolError> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        Ok(extrinsics.remove(hash).inspect(|extrinsic| {
            if let Some(hashes) = type_timeslot_index
                .get_mut(&(extrinsic.extrinsic_type.clone(), extrinsic.timeslot_index))
            {
                // Delete the hash entry being removed from the main storage
                hashes.retain(|&h| h != *hash);
                if hashes.is_empty() {
                    type_timeslot_index
                        .remove(&(extrinsic.extrinsic_type.clone(), extrinsic.timeslot_index));
                }
            }
        }))
    }
}
