#![allow(dead_code)]
use crate::pool::{OpaqueXtEntry, XtPool, XtPoolError};
use fr_block::types::extrinsics::{
    assurances::{AssurancesXt, AssurancesXtEntries, AssurancesXtEntry},
    disputes::{Culprit, DisputesXt, Fault, Verdict},
    guarantees::{GuaranteesXt, GuaranteesXtEntries, GuaranteesXtEntry},
    preimages::{PreimagesXt, PreimagesXtEntry},
    tickets::{TicketsXt, TicketsXtEntry},
    XtType,
};
use fr_codec::prelude::*;

struct XtManager;

impl XtManager {
    fn submit_extrinsic(
        pool: &XtPool,
        extrinsic: OpaqueXtEntry,
        timeslot_index: u32,
    ) -> Result<(), XtPoolError> {
        pool.add_extrinsic(extrinsic, timeslot_index)
    }

    fn get_extrinsics(
        pool: &XtPool,
        extrinsic_type: XtType,
        timeslot_index: u32,
    ) -> Result<Vec<OpaqueXtEntry>, XtPoolError> {
        pool.get_extrinsics_by_type_and_timeslot(extrinsic_type, timeslot_index)
    }

    // Getters for Extrinsic entries in a deserialized form
    pub fn get_ticket_extrinsics(
        pool: &XtPool,
        timeslot_index: u32,
    ) -> Result<TicketsXt, XtPoolError> {
        let items: Vec<TicketsXtEntry> =
            Self::get_extrinsics(pool, XtType::Ticket, timeslot_index)?
                .into_iter()
                .filter_map(|entry| TicketsXtEntry::decode(&mut entry.data.as_slice()).ok())
                .collect();
        Ok(TicketsXt { items })
    }

    pub fn get_guarantee_extrinsics(
        pool: &XtPool,
        timeslot_index: u32,
    ) -> Result<GuaranteesXt, XtPoolError> {
        let items_vec: Vec<GuaranteesXtEntry> =
            Self::get_extrinsics(pool, XtType::Guarantee, timeslot_index)?
                .into_iter()
                .filter_map(|entry| GuaranteesXtEntry::decode(&mut entry.data.as_slice()).ok())
                .collect();
        let items = GuaranteesXtEntries::try_from_vec(items_vec)?;
        Ok(GuaranteesXt { items })
    }

    pub fn get_assurance_extrinsics(
        pool: &XtPool,
        timeslot_index: u32,
    ) -> Result<AssurancesXt, XtPoolError> {
        let items_vec: Vec<AssurancesXtEntry> =
            Self::get_extrinsics(pool, XtType::Assurance, timeslot_index)?
                .into_iter()
                .filter_map(|entry| AssurancesXtEntry::decode(&mut entry.data.as_slice()).ok())
                .collect();
        let items = AssurancesXtEntries::try_from_vec(items_vec)?;
        Ok(AssurancesXt { items })
    }

    pub fn get_lookup_extrinsics(
        pool: &XtPool,
        timeslot_index: u32,
    ) -> Result<PreimagesXt, XtPoolError> {
        let items: Vec<PreimagesXtEntry> =
            Self::get_extrinsics(pool, XtType::PreimageLookup, timeslot_index)?
                .into_iter()
                .filter_map(|entry| PreimagesXtEntry::decode(&mut entry.data.as_slice()).ok())
                .collect();
        Ok(PreimagesXt { items })
    }

    pub fn get_dispute_extrinsics(
        pool: &XtPool,
        timeslot_index: u32,
    ) -> Result<DisputesXt, XtPoolError> {
        let verdicts: Vec<Verdict> = Self::get_extrinsics(pool, XtType::Verdict, timeslot_index)?
            .into_iter()
            .filter_map(|entry| Verdict::decode(&mut entry.data.as_slice()).ok())
            .collect();

        let culprits: Vec<Culprit> = Self::get_extrinsics(pool, XtType::Culprit, timeslot_index)?
            .into_iter()
            .filter_map(|entry| Culprit::decode(&mut entry.data.as_slice()).ok())
            .collect();

        let faults: Vec<Fault> = Self::get_extrinsics(pool, XtType::Fault, timeslot_index)?
            .into_iter()
            .filter_map(|entry| Fault::decode(&mut entry.data.as_slice()).ok())
            .collect();

        Ok(DisputesXt {
            verdicts,
            culprits,
            faults,
        })
    }
}
