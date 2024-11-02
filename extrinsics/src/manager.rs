#![allow(dead_code)]
use crate::pool::{ExtrinsicEntry, ExtrinsicType, ExtrinsicsPoolError, EXTRINSICS_POOL};
use rjam_codec::JamDecode;
use rjam_types::extrinsics::{
    assurances::{AssurancesExtrinsic, AssurancesExtrinsicEntry},
    disputes::{Culprit, DisputesExtrinsic, Fault, Verdict},
    guarantees::{GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
    preimages::{PreimageLookupsExtrinsic, PreimageLookupsExtrinsicEntry},
    tickets::{TicketsExtrinsic, TicketsExtrinsicEntry},
};

// TODO: add submitter that accepts `Extrinsic` type (not Entry Type) with encoding
fn submit_extrinsic(extrinsic: ExtrinsicEntry) -> Result<(), ExtrinsicsPoolError> {
    EXTRINSICS_POOL.write().unwrap().add_extrinsic(extrinsic)
}

fn get_extrinsics(
    extrinsic_type: ExtrinsicType,
    timeslot_index: u32,
) -> Result<Vec<ExtrinsicEntry>, ExtrinsicsPoolError> {
    EXTRINSICS_POOL
        .read()
        .unwrap()
        .get_extrinsics_by_type_and_timeslot(extrinsic_type, timeslot_index)
}

// Getters for Extrinsic entries in a deserialized form
pub fn get_ticket_extrinsics(timeslot_index: u32) -> Result<TicketsExtrinsic, ExtrinsicsPoolError> {
    let items: Vec<TicketsExtrinsicEntry> = get_extrinsics(ExtrinsicType::Ticket, timeslot_index)?
        .into_iter()
        .filter_map(|entry| TicketsExtrinsicEntry::decode(&mut entry.data.as_slice()).ok())
        .collect();
    Ok(TicketsExtrinsic { items })
}

pub fn get_guarantee_extrinsics(
    timeslot_index: u32,
) -> Result<GuaranteesExtrinsic, ExtrinsicsPoolError> {
    let items: Vec<GuaranteesExtrinsicEntry> =
        get_extrinsics(ExtrinsicType::Guarantee, timeslot_index)?
            .into_iter()
            .filter_map(|entry| GuaranteesExtrinsicEntry::decode(&mut entry.data.as_slice()).ok())
            .collect();
    Ok(GuaranteesExtrinsic { items })
}

pub fn get_assurance_extrinsics(
    timeslot_index: u32,
) -> Result<AssurancesExtrinsic, ExtrinsicsPoolError> {
    let items: Vec<AssurancesExtrinsicEntry> =
        get_extrinsics(ExtrinsicType::Assurance, timeslot_index)?
            .into_iter()
            .filter_map(|entry| AssurancesExtrinsicEntry::decode(&mut entry.data.as_slice()).ok())
            .collect();
    Ok(AssurancesExtrinsic { items })
}

pub fn get_lookup_extrinsics(
    timeslot_index: u32,
) -> Result<PreimageLookupsExtrinsic, ExtrinsicsPoolError> {
    let items: Vec<PreimageLookupsExtrinsicEntry> =
        get_extrinsics(ExtrinsicType::PreimageLookup, timeslot_index)?
            .into_iter()
            .filter_map(|entry| {
                PreimageLookupsExtrinsicEntry::decode(&mut entry.data.as_slice()).ok()
            })
            .collect();
    Ok(PreimageLookupsExtrinsic { items })
}

pub fn get_dispute_extrinsics(
    timeslot_index: u32,
) -> Result<DisputesExtrinsic, ExtrinsicsPoolError> {
    let verdicts: Vec<Verdict> = get_extrinsics(ExtrinsicType::Verdict, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Verdict::decode(&mut entry.data.as_slice()).ok())
        .collect();

    let culprits: Vec<Culprit> = get_extrinsics(ExtrinsicType::Culprit, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Culprit::decode(&mut entry.data.as_slice()).ok())
        .collect();

    let faults: Vec<Fault> = get_extrinsics(ExtrinsicType::Fault, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Fault::decode(&mut entry.data.as_slice()).ok())
        .collect();
    Ok(DisputesExtrinsic {
        verdicts,
        culprits,
        faults,
    })
}
