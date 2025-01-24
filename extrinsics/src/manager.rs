#![allow(dead_code)]
use crate::pool::{ExtrinsicEntry, ExtrinsicType, ExtrinsicsPool, ExtrinsicsPoolError};
use rjam_codec::JamDecode;
use rjam_types::extrinsics::{
    assurances::{AssurancesXt, AssurancesXtEntry},
    disputes::{Culprit, DisputesXt, Fault, Verdict},
    guarantees::{GuaranteesXt, GuaranteesXtEntry},
    preimages::{PreimagesXt, PreimagesXtEntry},
    tickets::{TicketsXt, TicketsXtEntry},
};

// TODO: add submitter that accepts `Extrinsic` type (not Entry Type) with encoding
fn submit_extrinsic(
    pool: &ExtrinsicsPool,
    extrinsic: ExtrinsicEntry,
) -> Result<(), ExtrinsicsPoolError> {
    pool.add_extrinsic(extrinsic)
}

fn get_extrinsics(
    pool: &ExtrinsicsPool,
    extrinsic_type: ExtrinsicType,
    timeslot_index: u32,
) -> Result<Vec<ExtrinsicEntry>, ExtrinsicsPoolError> {
    pool.get_extrinsics_by_type_and_timeslot(extrinsic_type, timeslot_index)
}

// Getters for Extrinsic entries in a deserialized form
pub fn get_ticket_extrinsics(
    pool: &ExtrinsicsPool,
    timeslot_index: u32,
) -> Result<TicketsXt, ExtrinsicsPoolError> {
    let items: Vec<TicketsXtEntry> = get_extrinsics(pool, ExtrinsicType::Ticket, timeslot_index)?
        .into_iter()
        .filter_map(|entry| TicketsXtEntry::decode(&mut entry.data.as_slice()).ok())
        .collect();
    Ok(TicketsXt { items })
}

pub fn get_guarantee_extrinsics(
    pool: &ExtrinsicsPool,
    timeslot_index: u32,
) -> Result<GuaranteesXt, ExtrinsicsPoolError> {
    let items: Vec<GuaranteesXtEntry> =
        get_extrinsics(pool, ExtrinsicType::Guarantee, timeslot_index)?
            .into_iter()
            .filter_map(|entry| GuaranteesXtEntry::decode(&mut entry.data.as_slice()).ok())
            .collect();
    Ok(GuaranteesXt { items })
}

pub fn get_assurance_extrinsics(
    pool: &ExtrinsicsPool,
    timeslot_index: u32,
) -> Result<AssurancesXt, ExtrinsicsPoolError> {
    let items: Vec<AssurancesXtEntry> =
        get_extrinsics(pool, ExtrinsicType::Assurance, timeslot_index)?
            .into_iter()
            .filter_map(|entry| AssurancesXtEntry::decode(&mut entry.data.as_slice()).ok())
            .collect();
    Ok(AssurancesXt { items })
}

pub fn get_lookup_extrinsics(
    pool: &ExtrinsicsPool,
    timeslot_index: u32,
) -> Result<PreimagesXt, ExtrinsicsPoolError> {
    let items: Vec<PreimagesXtEntry> =
        get_extrinsics(pool, ExtrinsicType::PreimageLookup, timeslot_index)?
            .into_iter()
            .filter_map(|entry| PreimagesXtEntry::decode(&mut entry.data.as_slice()).ok())
            .collect();
    Ok(PreimagesXt { items })
}

pub fn get_dispute_extrinsics(
    pool: &ExtrinsicsPool,
    timeslot_index: u32,
) -> Result<DisputesXt, ExtrinsicsPoolError> {
    let verdicts: Vec<Verdict> = get_extrinsics(pool, ExtrinsicType::Verdict, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Verdict::decode(&mut entry.data.as_slice()).ok())
        .collect();

    let culprits: Vec<Culprit> = get_extrinsics(pool, ExtrinsicType::Culprit, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Culprit::decode(&mut entry.data.as_slice()).ok())
        .collect();

    let faults: Vec<Fault> = get_extrinsics(pool, ExtrinsicType::Fault, timeslot_index)?
        .into_iter()
        .filter_map(|entry| Fault::decode(&mut entry.data.as_slice()).ok())
        .collect();
    Ok(DisputesXt {
        verdicts,
        culprits,
        faults,
    })
}
