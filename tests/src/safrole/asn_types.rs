use crate::{
    asn_types::{
        validators_data_to_validator_set, BandersnatchKey, ByteArray32, Ed25519Key, OpaqueHash,
        ValidatorsData, EPOCH_LENGTH, VALIDATORS_COUNT,
    },
    test_utils::{deserialize_hex_array, serialize_hex_array},
};
use rjam_common::{BandersnatchPubKey, Ticket};
use rjam_transition::procedures::chain_extension::SafroleHeaderMarkers;
use rjam_types::{
    block::header::EpochMarker,
    extrinsics::tickets::TicketsExtrinsicEntry,
    state::{
        entropy::EntropyAccumulator,
        safrole::{SafroleState, SlotSealerType, TicketAccumulator},
    },
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub type EpochKeys = [BandersnatchKey; EPOCH_LENGTH];
pub type TicketsBodies = [TicketBody; EPOCH_LENGTH];

// Define enumerations
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TicketsOrKeys {
    tickets(TicketsBodies),
    keys(EpochKeys),
}

impl From<TicketsOrKeys> for SlotSealerType {
    fn from(value: TicketsOrKeys) -> Self {
        match value {
            TicketsOrKeys::tickets(ticket_bodies) => {
                let mut tickets: [Ticket; EPOCH_LENGTH] = Default::default();
                for (i, ticket_body) in ticket_bodies.into_iter().enumerate() {
                    tickets[i] = Ticket {
                        id: ticket_body.id.0,
                        attempt: ticket_body.attempt,
                    };
                }
                SlotSealerType::Tickets(Box::new(tickets))
            }
            TicketsOrKeys::keys(epoch_keys) => {
                let mut keys: [BandersnatchPubKey; EPOCH_LENGTH] = Default::default();
                for (i, key) in epoch_keys.into_iter().enumerate() {
                    keys[i] = key.0
                }
                SlotSealerType::BandersnatchPubKeys(Box::new(keys))
            }
        }
    }
}

impl From<SlotSealerType> for TicketsOrKeys {
    fn from(value: SlotSealerType) -> Self {
        match value {
            SlotSealerType::Tickets(tickets) => {
                let mut ticket_bodies: TicketsBodies = Default::default();
                for (i, ticket) in tickets.into_iter().enumerate() {
                    ticket_bodies[i] = TicketBody {
                        id: ByteArray32(ticket.id),
                        attempt: ticket.attempt,
                    };
                }
                TicketsOrKeys::tickets(ticket_bodies)
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                let mut epoch_keys: EpochKeys = Default::default();
                for (i, key) in keys.into_iter().enumerate() {
                    epoch_keys[i] = ByteArray32(key);
                }
                TicketsOrKeys::keys(epoch_keys)
            }
        }
    }
}

// State transition function execution error.
// Error codes are not specified in the Graypaper.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum CustomErrorCode {
    bad_slot,           // Timeslot value must be strictly monotonic
    unexpected_ticket,  // Received a ticket while in epoch's tail
    bad_ticket_order,   // Tickets must be sorted
    bad_ticket_proof,   // Invalid ticket ring proof
    bad_ticket_attempt, // Invalid ticket attempt value
    reserved,           // Reserved
    duplicate_ticket,   // Found a ticket duplicate
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy, PartialEq)]
pub struct TicketBody {
    pub id: OpaqueHash,
    pub attempt: u8,
}

impl From<Ticket> for TicketBody {
    fn from(ticket: Ticket) -> Self {
        TicketBody {
            id: ByteArray32(ticket.id),
            attempt: ticket.attempt,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct TicketEnvelope {
    attempt: u8,
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    signature: [u8; 784],
}

impl From<TicketEnvelope> for TicketsExtrinsicEntry {
    fn from(envelope: TicketEnvelope) -> Self {
        TicketsExtrinsicEntry {
            ticket_proof: Box::new(envelope.signature),
            entry_index: envelope.attempt,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EpochMark {
    entropy: OpaqueHash,
    validators: [BandersnatchKey; VALIDATORS_COUNT],
}

impl From<EpochMarker> for EpochMark {
    fn from(marker: EpochMarker) -> Self {
        EpochMark {
            entropy: ByteArray32(marker.entropy),
            validators: marker.validators.map(ByteArray32),
        }
    }
}

pub type TicketsMark = [TicketBody; EPOCH_LENGTH];

// Output markers
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct OutputMarks {
    epoch_mark: Option<EpochMark>,     // New epoch signal
    tickets_mark: Option<TicketsMark>, // Tickets signal
}

impl From<SafroleHeaderMarkers> for OutputMarks {
    fn from(value: SafroleHeaderMarkers) -> Self {
        Self {
            epoch_mark: value.epoch_marker.map(EpochMark::from),
            tickets_mark: value
                .winning_tickets_marker
                .map(|tickets| tickets.map(TicketBody::from)),
        }
    }
}

// State relevant to Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub tau: u32,                 // Most recent block's timeslot
    pub eta: [OpaqueHash; 4],     // Entropy accumulator and epochal randomness
    pub lambda: ValidatorsData, // Validator keys and metadata which were active in the prior epoch
    pub kappa: ValidatorsData,  // Validator keys and metadata currently active
    pub gamma_k: ValidatorsData, // Validator keys for the following epoch
    pub iota: ValidatorsData,   // Validator keys and metadata to be drawn from next
    pub gamma_a: Vec<TicketBody>, // Sealing-key contest ticket accumulator; size up to `EPOCH_LENGTH`
    pub gamma_s: TicketsOrKeys,   // Sealing-key series of the current epoch
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub gamma_z: [u8; 144], // Bandersnatch ring commitment
}

impl From<&State> for SafroleState {
    fn from(value: &State) -> Self {
        SafroleState {
            pending_set: validators_data_to_validator_set(&value.gamma_k),
            ring_root: value.gamma_z.clone().into(),
            slot_sealers: SlotSealerType::from(value.gamma_s.clone()),
            ticket_accumulator: TicketAccumulator::from_vec(
                value
                    .gamma_a
                    .iter()
                    .map(|ticket_body| Ticket {
                        id: ticket_body.id.0,
                        attempt: ticket_body.attempt,
                    })
                    .collect(),
            ),
        }
    }
}

impl From<&State> for EntropyAccumulator {
    fn from(value: &State) -> Self {
        EntropyAccumulator(value.eta.clone().map(|entropy| entropy.0))
    }
}

// Input for Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: u32,                       // Current slot
    pub entropy: OpaqueHash, // Per block entropy (originated from block entropy source VRF)
    pub extrinsic: Vec<TicketEnvelope>, // Safrole extrinsic; size up to 16
    pub post_offenders: Vec<Ed25519Key>, // Offenders sequence
}

// Output from Safrole protocol
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    ok(OutputMarks),      // Markers
    err(CustomErrorCode), // Error code (not specified in the Graypaper)
}

// Safrole state transition function execution dump
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestCase {
    pub input: Input,      // Input
    pub pre_state: State,  // Pre-execution state
    pub output: Output,    // Output
    pub post_state: State, // Post-execution state
}
