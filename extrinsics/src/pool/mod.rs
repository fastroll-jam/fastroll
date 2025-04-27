use rjam_block::types::extrinsics::{
    disputes::{Culprit, Fault, Verdict},
    ExtrinsicsError, XtEntry, XtType,
};
use rjam_common::Hash32;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
};
use thiserror::Error;

type XtMap = Arc<RwLock<HashMap<Hash32, OpaqueXtEntry>>>;
type TypeTimeslotIndex = Arc<RwLock<BTreeMap<(XtType, u32), Vec<Hash32>>>>; // u32 for timeslot index

#[derive(Debug, Error)]
pub enum XtPoolError {
    #[error("Extrinsics pool is full")]
    Full,
    #[error("ExtrinsicsError: {0}")]
    ExtrinsicsError(#[from] ExtrinsicsError),
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum DisputesEntryType {
    Verdict(Verdict),
    Culprit(Culprit),
    Fault(Fault),
}

/// Extrinsics entry stored to the main `XtPool` in-memory pool
#[derive(Clone)]
pub struct OpaqueXtEntry {
    pub hash: Hash32,
    pub data: Vec<u8>, // serialized extrinsic data
    pub extrinsic_type: XtType,
}

impl OpaqueXtEntry {
    pub fn from_xt_entry<E: XtEntry>(xt: E) -> Result<Self, ExtrinsicsError> {
        Ok(Self {
            hash: xt.hash()?,
            data: xt.encode()?,
            extrinsic_type: E::XT_TYPE,
        })
    }
}

/// Main in-memory data structure for storing unprocessed extrinsics
pub struct XtPool {
    /// Main storage
    pub extrinsics: XtMap,
    /// Index for type and timeslot lookups
    type_timeslot_index: TypeTimeslotIndex,
    /// Maximum size of the pool
    max_size: usize,
}

impl XtPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            extrinsics: Arc::new(RwLock::new(HashMap::new())),
            type_timeslot_index: Arc::new(RwLock::new(BTreeMap::new())),
            max_size,
        }
    }

    /// Adds an extrinsic entry to the in-memory pool
    pub fn add_extrinsic(
        &self,
        entry: OpaqueXtEntry,
        timeslot_index: u32,
    ) -> Result<(), XtPoolError> {
        let mut extrinsics = self.extrinsics.write().unwrap();
        let mut type_timeslot_index = self.type_timeslot_index.write().unwrap();

        if extrinsics.len() >= self.max_size {
            return Err(XtPoolError::Full);
        }

        // Add to the main storage
        extrinsics.insert(entry.hash.clone(), entry.clone());

        // Add to the type-timeslot lookup index
        type_timeslot_index
            .entry((entry.extrinsic_type.clone(), timeslot_index))
            .or_default()
            .push(entry.hash);

        Ok(())
    }

    /// Reads an extrinsic entry from the in-memory pool
    pub fn get_extrinsics_by_type_and_timeslot(
        &self,
        extrinsic_type: XtType,
        timeslot_index: u32,
    ) -> Result<Vec<OpaqueXtEntry>, XtPoolError> {
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
    pub fn remove_extrinsic(&self, _hash: &Hash32) -> Result<Option<OpaqueXtEntry>, XtPoolError> {
        unimplemented!()
    }
}
