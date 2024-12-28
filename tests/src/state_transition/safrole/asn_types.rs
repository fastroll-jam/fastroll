use crate::asn_types::{
    validators_data_to_validator_set, AsnBandersnatchRingRoot, AsnEd25519Key, AsnEntropyBuffer,
    AsnEpochMark, AsnOpaqueHash, AsnTicketBody, AsnTicketEnvelope, AsnTicketsMark,
    AsnTicketsOrKeys, AsnValidatorsData,
};
use rjam_common::{ByteArray, Hash32, Ticket};
use rjam_transition::procedures::chain_extension::SafroleHeaderMarkers;
use rjam_types::{extrinsics::tickets::TicketsExtrinsic, state::*};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SafroleErrorCode {
    bad_slot,           // Timeslot value must be strictly monotonic
    unexpected_ticket,  // Received a ticket while in epoch's tail
    bad_ticket_order,   // Tickets must be sorted
    bad_ticket_proof,   // Invalid ticket ring proof
    bad_ticket_attempt, // Invalid ticket attempt value
    reserved,           // Reserved
    duplicate_ticket,   // Found a ticket duplicate
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct AsnOutputMarks {
    pub epoch_mark: Option<AsnEpochMark>,     // New epoch signal
    pub tickets_mark: Option<AsnTicketsMark>, // Tickets signal
}

impl From<SafroleHeaderMarkers> for AsnOutputMarks {
    fn from(value: SafroleHeaderMarkers) -> Self {
        Self {
            epoch_mark: value.epoch_marker.map(AsnEpochMark::from),
            tickets_mark: value
                .winning_tickets_marker
                .map(|tickets| tickets.map(AsnTicketBody::from)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub tau: u32,                           // Most recent block's timeslot
    pub eta: AsnEntropyBuffer,              // Entropy accumulator and epochal randomness
    pub lambda: AsnValidatorsData, // Validator keys and metadata which were active in the prior epoch
    pub kappa: AsnValidatorsData,  // Validator keys and metadata currently active
    pub gamma_k: AsnValidatorsData, // Validator keys for the following epoch
    pub iota: AsnValidatorsData,   // Validator keys and metadata to be drawn from next
    pub gamma_a: Vec<AsnTicketBody>, // Sealing-key contest ticket accumulator; size up to `EPOCH_LENGTH`
    pub gamma_s: AsnTicketsOrKeys,   // Sealing-key series of the current epoch
    pub gamma_z: AsnBandersnatchRingRoot, // Bandersnatch ring commitment
    pub post_offenders: Vec<AsnEd25519Key>, // Offenders sequence
}

impl From<&State> for SafroleState {
    fn from(value: &State) -> Self {
        SafroleState {
            pending_set: validators_data_to_validator_set(&value.gamma_k),
            ring_root: ByteArray::new(value.gamma_z.0),
            slot_sealers: SlotSealerType::from(value.gamma_s.clone()),
            ticket_accumulator: TicketAccumulator::from_vec(
                value
                    .gamma_a
                    .iter()
                    .map(|ticket_body| Ticket {
                        id: ByteArray::new(ticket_body.id.0),
                        attempt: ticket_body.attempt,
                    })
                    .collect(),
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: u32,                         // Current slot
    pub entropy: AsnOpaqueHash, // Per block entropy (originated from block entropy source VRF)
    pub extrinsic: Vec<AsnTicketEnvelope>, // Safrole extrinsic; size up to 16
}

pub struct JamInput {
    pub slot: Timeslot,
    pub entropy: Hash32,
    pub extrinsic: TicketsExtrinsic,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(AsnOutputMarks),    // Markers
    err(SafroleErrorCode), // Error code (not specified in the Graypaper)
}
