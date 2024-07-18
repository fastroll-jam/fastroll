mod merklization;

use crate::codec::{
    encode_length_discriminated_sorted_field, encode_optional_field,
    size_hint_length_discriminated_sorted_field, size_hint_optional_field,
};
use crate::{
    codec::{
        encode_length_discriminated_field, encode_length_discriminated_optional_field,
        size_hint_length_discriminated_field, size_hint_length_discriminated_optional_field,
    },
    common::{
        BandersnatchPubKey, BandersnatchRingRoot, Ed25519PubKey, Hash32, Octets, Ticket,
        UnsignedGas, WorkReport, CORE_COUNT, EPOCH_LENGTH, VALIDATOR_COUNT,
    },
};
use parity_scale_codec::{Encode, Output};
use std::collections::{BTreeMap, HashMap};

type ValidatorKey = [u8; 336];

pub struct GlobalState {
    recent_timeslot: u32,                                             // tau
    safrole_state: SafroleState,                                      // gamma
    staging_validator_set: [ValidatorKey; VALIDATOR_COUNT],           // iota
    active_validator_set: [ValidatorKey; VALIDATOR_COUNT],            // kappa
    past_validator_set: [ValidatorKey; VALIDATOR_COUNT],              // lambda
    entropy_accumulator: [Hash32; 4],                                 // eta
    service_accounts: BTreeMap<u32, ServiceAccountState>, // sigma
    privileged_services: PrivilegedServicesState,        // chi
    pending_reports: PendingReports,                     // rho
    authorization_pool: AuthorizationPool,               // alpha
    authorization_queue: [[Hash32; 80]; CORE_COUNT],     // phi
    block_history: Vec<BlockHistoryEntry>, // beta; Vec<BlockHistoryEntry> length up to `H = 8`.
    verdicts: VerdictsState,               // psi
    validator_statistics: [[ValidatorStatEntry; VALIDATOR_COUNT]; 2], // pi
}

struct SafroleState {
    pending_validator_set: [ValidatorKey; VALIDATOR_COUNT], // gamma_k
    ring_root: BandersnatchRingRoot,                        // gamma_z
    slot_sealers: SlotSealerType,                           // gamma_s
    ticket_accumulator: Vec<Ticket>,                        // gamma_a; max length EPOCH_LENGTH
}

impl Encode for SafroleState {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.pending_validator_set.encode_to(dest);
        self.ring_root.encode_to(dest);
        self.slot_sealers.encode_to(dest);
        encode_length_discriminated_field(&self.ticket_accumulator, dest);
    }
}

enum SlotSealerType {
    Tickets(Box<[Ticket; EPOCH_LENGTH]>),
    BandersnatchPubKeys(Box<[BandersnatchPubKey; EPOCH_LENGTH]>),
}

impl Encode for SlotSealerType {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            SlotSealerType::Tickets(tickets) => {
                0u8.encode_to(dest);
                tickets.encode_to(dest);
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                1u8.encode_to(dest);
                keys.encode_to(dest);
            }
        }
    }
}

struct ServiceAccountState {
    storage: HashMap<Hash32, Octets>,          // s
    preimages: HashMap<Hash32, Octets>,        // p
    lookups: HashMap<(Hash32, u32), Vec<u32>>, // l; Vec<u32> length up to 3
    code_hash: Hash32,                         // c
    balance: u64,                              // b
    gas_limit_accumulate: UnsignedGas,         // g
    gas_limit_on_transfer: UnsignedGas,        // m
}

#[derive(Encode)]
struct PrivilegedServicesState {
    empower_service_index: u32,   // m; N_S
    assign_service_index: u32,    // a; N_S
    designate_service_index: u32, // v; N_S
}

struct PendingReports {
    entries: [Option<PendingReport>; CORE_COUNT],
}

impl Encode for PendingReports {
    fn size_hint(&self) -> usize {
        self.entries.iter().map(size_hint_optional_field).sum()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        for entry in &self.entries {
            encode_optional_field(entry, dest);
        }
    }
}

struct PendingReport {
    work_report: WorkReport,
    timeslot: u32,
}

impl Encode for PendingReport {
    fn size_hint(&self) -> usize {
        self.work_report.size_hint() + self.timeslot.size_hint()
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.work_report.encode_to(dest);
        self.timeslot.encode_to(dest);
    }
}

struct AuthorizationPool {
    entries: [Vec<Hash32>; CORE_COUNT], // Vec<Hash32> length up to `O = 8`
}

impl Encode for AuthorizationPool {
    fn size_hint(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| size_hint_length_discriminated_field(entry))
            .sum()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        for entry in &self.entries {
            encode_length_discriminated_field(entry, dest);
        }
    }
}

struct BlockHistoryEntry {
    header_hash: Hash32,
    accumulation_result_root: Vec<Option<Hash32>>, // MMR
    state_root: Hash32,
    work_report_hashes: Vec<Hash32>, // length up to `C = 341`.
}

impl Encode for BlockHistoryEntry {
    fn size_hint(&self) -> usize {
        self.header_hash.size_hint()
            + size_hint_length_discriminated_optional_field(&self.accumulation_result_root)
            + self.state_root.size_hint()
            + size_hint_length_discriminated_field(&self.work_report_hashes)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.header_hash.encode_to(dest);
        encode_length_discriminated_optional_field(&self.accumulation_result_root, dest); // E_M; MMR encoding
        self.state_root.encode_to(dest);
        encode_length_discriminated_field(&self.work_report_hashes, dest);
    }
}

struct VerdictsState {
    good_set: Vec<Hash32>,          // psi_g; recording hash of correct work-reports
    bad_set: Vec<Hash32>,           // psi_b; recording hash of incorrect work-reports
    wonky_set: Vec<Hash32>,         // psi_w; recording hash of work-reports that cannot be judged
    punish_set: Vec<Ed25519PubKey>, // psi_p; recording Ed25519 public keys of validators which have misjudged.
}

impl Encode for VerdictsState {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_sorted_field(&self.good_set)
            + size_hint_length_discriminated_sorted_field(&self.bad_set)
            + size_hint_length_discriminated_sorted_field(&self.wonky_set)
            + size_hint_length_discriminated_sorted_field(&self.punish_set)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_sorted_field(&self.good_set, dest);
        encode_length_discriminated_sorted_field(&self.bad_set, dest);
        encode_length_discriminated_sorted_field(&self.wonky_set, dest);
        encode_length_discriminated_sorted_field(&self.punish_set, dest);
    }
}

#[derive(Encode)]
struct ValidatorStatEntry {
    block_production_count: u32, // b; the number of blocks produced by the validator.
    ticket_count: u32,           // t; the number of tickets introduced by the validator.
    preimage_count: u32,         // p; the number of preimages introduced by the validator.
    preimage_data_octet_count: u32, // d; the total number of octets across all preimages introduced by the validator.
    guarantee_count: u32,           // g; the number of reports guaranteed by the validator.
    assurance_count: u32, // a; the number of availability assurances made by the validator.
}
