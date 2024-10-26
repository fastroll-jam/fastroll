#![allow(dead_code)]
use crate::extrinsics_pool::{ExtrinsicEntry, ExtrinsicType, EXTRINSICS_POOL};
use rjam_codec::JamDecode;
use rjam_types::{
    extrinsics::{
        assurances::AssurancesExtrinsicEntry, guarantees::GuaranteesExtrinsicEntry,
        preimages::PreimageLookupsExtrinsicEntry, tickets::TicketsExtrinsicEntry,
    },
    state::timeslot::Timeslot,
};

// TODO: add submitter that accepts `Extrinsic` type (not Entry Type) with encoding

fn submit_extrinsic(extrinsic: ExtrinsicEntry) -> Result<(), String> {
    EXTRINSICS_POOL.write().unwrap().add_extrinsic(extrinsic)
}

fn get_extrinsics(extrinsic_type: ExtrinsicType, timeslot: Timeslot) -> Vec<ExtrinsicEntry> {
    EXTRINSICS_POOL
        .read()
        .unwrap()
        .get_extrinsics_by_type_and_timeslot(extrinsic_type, timeslot)
}

// Getters for Extrinsic entries in a deserialized form
pub fn get_ticket_extrinsics(timeslot: Timeslot) -> Vec<TicketsExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Ticket, timeslot)
        .into_iter()
        .filter_map(|extrinsic| TicketsExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok())
        .collect()
}

pub fn get_guarantee_extrinsics(timeslot: Timeslot) -> Vec<GuaranteesExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Guarantee, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            GuaranteesExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}

pub fn get_assurance_extrinsics(timeslot: Timeslot) -> Vec<AssurancesExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Assurance, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            AssurancesExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}

pub fn get_lookup_extrinsics(timeslot: Timeslot) -> Vec<PreimageLookupsExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::PreimageLookup, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            PreimageLookupsExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}
