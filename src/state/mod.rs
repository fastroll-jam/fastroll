use crate::common::{
    BandersnatchPubKey, BandersnatchRingRoot, Ed25519PubKey, Hash32, Octets, Ticket, UnsignedGas,
    WorkReport, CORE_COUNT, EPOCH_LENGTH, VALIDATOR_COUNT,
};
use std::collections::HashMap;

type ValidatorKey = [u8; 336];

pub struct GlobalState {
    recent_timeslot: u32,                                             // tau
    safrole_state: SafroleState,                                      // gamma
    staging_validator_set: [ValidatorKey; VALIDATOR_COUNT],           // iota
    active_validator_set: [ValidatorKey; VALIDATOR_COUNT],            // kappa
    past_validator_set: [ValidatorKey; VALIDATOR_COUNT],              // lambda
    entropy_accumulator: [Hash32; 4],                                 // eta
    service_accounts: HashMap<u32, ServiceAccountState>, // sigma; TODO: use Merkle Trie instead
    privileged_services: PrivilegedServicesState,        // chi;
    pending_reports: [Option<PendingReport>; CORE_COUNT], // rho
    authorization_pool: [Vec<Hash32>; CORE_COUNT],       // alpha; Vec<Hash32> length up to `O = 8`.
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

enum SlotSealerType {
    Tickets(Box<[Ticket; EPOCH_LENGTH]>),
    BandersnatchPubKeys(Box<[BandersnatchPubKey; EPOCH_LENGTH]>),
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

struct PrivilegedServicesState {
    empower_service_index: u32,   // m; N_S
    assign_service_index: u32,    // a; N_S
    designate_service_index: u32, // v; N_S
}

struct PendingReport {
    work_report: WorkReport,
    timeslot: u32,
}

struct BlockHistoryEntry {
    header_hash: Hash32,
    accumulation_result_root: Vec<Option<Hash32>>,
    state_root: Hash32,
    work_report_hashes: Vec<Hash32>, // length up to `C = 341`.
}

struct VerdictsState {
    good_set: Vec<Hash32>,          // psi_g; recording hash of correct work-reports
    bad_set: Vec<Hash32>,           // psi_b; recording hash of incorrect work-reports
    wonky_set: Vec<Hash32>,         // psi_w; recording hash of work-reports that cannot be judged
    punish_set: Vec<Ed25519PubKey>, // psi_p; recording Ed25519 public keys of validators which have misjudged.
}

struct ValidatorStatEntry {
    block_production_count: u64, // b; the number of blocks produced by the validator.
    ticket_count: u64,           // t; the number of tickets introduced by the validator.
    preimage_count: u64,         // p; the number of preimages introduced by the validator.
    preimage_data_octet_count: u64, // d; the total number of octets across all preimages introduced by the validator.
    guarantee_count: u64,           // g; the number of reports guaranteed by the validator.
    assurance_count: u64, // a; the number of availability assurances made by the validator.
}
