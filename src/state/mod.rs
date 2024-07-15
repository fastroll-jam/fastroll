use crate::common::{
    BandersnatchPubKey, BandersnatchRingRoot, Ed25519PubKey, Hash32, Ticket, WorkReport,
    CORE_COUNT, EPOCH_LENGTH, VALIDATOR_COUNT,
};
use std::collections::HashMap;

type ValidatorKey = [u8; 336];

pub struct GlobalState {
    recent_timeslot: u32,
    safrole_state: SafroleState,
    staging_validator_set: [ValidatorKey; VALIDATOR_COUNT],
    active_validator_set: [ValidatorKey; VALIDATOR_COUNT],
    past_validator_set: [ValidatorKey; VALIDATOR_COUNT],
    entropy_accumulator: [Hash32; 4],
    service_accounts: HashMap<u32, ServiceAccountState>, // TODO: use Merkle Trie instead
    privileged_services: (u32, u32, u32),                // (chi_m, chi_a, chi_v)
    pending_reports: [Option<PendingReport>; CORE_COUNT],
    authorization_pool: [Vec<Hash32>; CORE_COUNT], // Vec<Hash32> length up to `O = 8`.
    authorization_queue: [[Hash32; 80]; CORE_COUNT],
    block_history: Vec<BlockHistoryEntry>, // Vec<BlockHistoryEntry> length up to `H = 8`.
    judgements: Vec<JudgementEntry>,
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

struct ServiceAccountState {}

struct PendingReport {
    work_report: WorkReport,
    guarantors: Vec<Ed25519PubKey>, // length range [2, 3]
    timeslot: u32,
}

struct BlockHistoryEntry {
    header_hash: Hash32,
    accumulation_result_root: Vec<Option<Hash32>>,
    state_root: Hash32,
    work_report_hashes: Vec<Hash32>, // length up to `C = 341`.
}

struct JudgementEntry {
    allow_set: Hash32,
    ban_set: Hash32,
    punish_set: Vec<BandersnatchPubKey>,
    last_epoch_validator_set: [ValidatorKey; VALIDATOR_COUNT],
}
