use crate::common::{
    BandersnatchRingVrfProof, Ed25519PubKey, Ed25519Signature, Ed25519SignatureWithKeyAndMessage,
    Hash32, Octet, WorkReport, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use bit_vec::BitVec;

type TicketsExtrinsic = Vec<TicketExtrinsicEntry>;
type GuaranteesExtrinsic = Vec<GuaranteeExtrinsicEntry>;
type AssurancesExtrinsic = Vec<AssuranceExtrinsicEntry>; // length up to VALIDATOR_COUNT
type PreimageLookupsExtrinsic = Vec<PreimageLookupExtrinsicEntry>;

pub struct Extrinsics {
    tickets_extrinsic: TicketsExtrinsic,                  // E_T
    guarantees_extrinsic: GuaranteesExtrinsic,            // E_G
    assurances_extrinsic: AssurancesExtrinsic,            // E_A
    preimage_lookups_extrinsic: PreimageLookupsExtrinsic, // E_P
    verdicts_extrinsic: VerdictsExtrinsic,                // E_V
}

struct TicketExtrinsicEntry {
    entry_index: u32,                       // r; N_N
    ticket_proof: BandersnatchRingVrfProof, // p
}
struct GuaranteeExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t; N_T
    credential: Vec<(u32, Ed25519Signature)>, // a; (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
}
struct AssuranceExtrinsicEntry {
    anchor_parent_hash: Hash32,    // a
    assuring_cores_bitvec: BitVec, // f
    validator_index: u32,          // v; N_V
    signature: Ed25519Signature,   // s
}
struct PreimageLookupExtrinsicEntry {
    service_index: u32, // N_S
    preimage_data: Octet,
}
struct VerdictsExtrinsic {
    verdicts: Vec<Verdict>, // v
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

struct Verdict {
    report_hash: Hash32,                                 // r
    epoch_index: u32,                                    // a
    votes: [Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1], // v
}

struct Vote {
    is_report_valid: bool,
    voter_index: u32, // N_V
    voter_signature: Ed25519SignatureWithKeyAndMessage,
}

struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}
