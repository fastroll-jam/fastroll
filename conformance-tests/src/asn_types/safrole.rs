use crate::asn_types::common::*;
use rjam_common::{BandersnatchRingRoot, Hash32};
use rjam_transition::procedures::chain_extension::SafroleHeaderMarkers;
use rjam_types::{extrinsics::tickets::TicketsXt, state::*};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SafroleErrorCode {
    /// Timeslot value must be strictly monotonic.
    bad_slot,
    /// Received a ticket while in epoch's tail.
    unexpected_ticket,
    /// Tickets must be sorted.
    bad_ticket_order,
    /// Invalid ticket ring proof.
    bad_ticket_proof,
    /// Invalid ticket attempt value.
    bad_ticket_attempt,
    /// Reserved.
    reserved,
    /// Found a ticket duplicate.
    duplicate_ticket,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct AsnOutputMarks {
    /// New epoch signal.
    pub epoch_mark: Option<AsnEpochMark>,
    /// Tickets signal.
    pub tickets_mark: Option<AsnTicketsMark>,
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
    /// Most recent block's timeslot.
    pub tau: u32,
    /// Entropy accumulator and epochal randomness.
    pub eta: AsnEntropyBuffer,
    /// Validator keys and metadata which were active in the prior epoch.
    pub lambda: AsnValidatorsData,
    /// Validator keys and metadata currently active.
    pub kappa: AsnValidatorsData,
    /// Validator keys for the following epoch.
    pub gamma_k: AsnValidatorsData,
    /// Validator keys and metadata to be drawn from next.
    pub iota: AsnValidatorsData,
    /// Sealing-key contest ticket accumulator; size up to `EPOCH_LENGTH`.
    pub gamma_a: Vec<AsnTicketBody>,
    /// Sealing-key series of the current epoch.
    pub gamma_s: AsnTicketsOrKeys,
    /// Bandersnatch ring commitment.
    pub gamma_z: AsnBandersnatchRingRoot,
    /// Offenders sequence.
    pub post_offenders: Vec<AsnEd25519Key>,
}

impl From<&State> for SafroleState {
    fn from(value: &State) -> Self {
        SafroleState {
            pending_set: validators_data_to_validator_set(&value.gamma_k),
            ring_root: BandersnatchRingRoot::from(value.gamma_z),
            slot_sealers: SlotSealerType::from(value.gamma_s.clone()),
            ticket_accumulator: TicketAccumulator::from_vec(
                value
                    .gamma_a
                    .iter()
                    .map(|ticket_body| Ticket {
                        id: Hash32::from(ticket_body.id),
                        attempt: ticket_body.attempt,
                    })
                    .collect(),
            ),
        }
    }
}

pub fn safrole_state_to_gammas(
    safrole: SafroleState,
) -> (
    AsnValidatorsData,
    Vec<AsnTicketBody>,
    AsnTicketsOrKeys,
    AsnBandersnatchRingRoot,
) {
    let gamma_k = safrole.pending_set.map(AsnValidatorData::from);
    let gamma_a = safrole
        .ticket_accumulator
        .clone()
        .into_vec()
        .into_iter()
        .map(|ticket| AsnTicketBody {
            id: AsnOpaqueHash::from(ticket.id),
            attempt: ticket.attempt,
        })
        .collect();
    let gamma_s = safrole.slot_sealers.into();
    let gamma_z = AsnBandersnatchRingRoot::from(safrole.ring_root);
    (gamma_k, gamma_a, gamma_s, gamma_z)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    /// Current slot.
    pub slot: u32,
    /// Epoch entropy.
    pub entropy: AsnOpaqueHash,
    /// Tickets extrinsic; size up to 16.
    pub extrinsic: Vec<AsnTicketEnvelope>,
}

pub struct JamInput {
    pub slot: Timeslot,
    pub entropy: Hash32,
    pub extrinsic: TicketsXt,
}

#[allow(non_camel_case_types, clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Output {
    /// Output markers.
    ok(AsnOutputMarks),
    /// Error code (not specified in the Graypaper).
    err(SafroleErrorCode),
}
