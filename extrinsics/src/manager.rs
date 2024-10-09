use crate::extrinsics_pool::{ExtrinsicEntry, ExtrinsicType, EXTRINSICS_POOL};
use rjam_codec::JamDecode;
use rjam_types::{
    extrinsics::{
        assurances::AssuranceExtrinsicEntry, guarantees::GuaranteeExtrinsicEntry,
        preimages::PreimageLookupExtrinsicEntry, tickets::TicketExtrinsicEntry,
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
pub fn get_ticket_extrinsics(timeslot: Timeslot) -> Vec<TicketExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Ticket, timeslot)
        .into_iter()
        .filter_map(|extrinsic| TicketExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok())
        .collect()
}

pub fn get_guarantee_extrinsics(timeslot: Timeslot) -> Vec<GuaranteeExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Guarantee, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            GuaranteeExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}

pub fn get_assurance_extrinsics(timeslot: Timeslot) -> Vec<AssuranceExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::Assurance, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            AssuranceExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}

pub fn get_lookup_extrinsics(timeslot: Timeslot) -> Vec<PreimageLookupExtrinsicEntry> {
    get_extrinsics(ExtrinsicType::PreimageLookup, timeslot)
        .into_iter()
        .filter_map(|extrinsic| {
            PreimageLookupExtrinsicEntry::decode(&mut extrinsic.data.as_slice()).ok()
        })
        .collect()
}
