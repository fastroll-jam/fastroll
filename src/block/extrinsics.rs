use crate::{
    codec::{encode_length_discriminated_field, size_hint_length_discriminated_field},
    common::{
        BandersnatchRingVrfProof, Ed25519PubKey, Ed25519Signature,
        Ed25519SignatureWithKeyAndMessage, Hash32, Octets, WorkReport,
        FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
    },
};
use bit_vec::BitVec;
use parity_scale_codec::{Compact, Encode, Output};

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

impl Encode for Extrinsics {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_field(&self.tickets_extrinsic)
            + self.verdicts_extrinsic.size_hint()
            + size_hint_length_discriminated_field(&self.preimage_lookups_extrinsic)
            + size_hint_length_discriminated_field(&self.assurances_extrinsic)
            + size_hint_length_discriminated_field(&self.guarantees_extrinsic)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_field(&self.tickets_extrinsic, dest);
        self.verdicts_extrinsic.encode_to(dest);
        encode_length_discriminated_field(&self.preimage_lookups_extrinsic, dest);
        encode_length_discriminated_field(&self.assurances_extrinsic, dest);
        encode_length_discriminated_field(&self.guarantees_extrinsic, dest);
    }
}

#[derive(Encode)]
struct TicketExtrinsicEntry {
    entry_index: u32,                       // r; N_N
    ticket_proof: BandersnatchRingVrfProof, // p
}

struct GuaranteeExtrinsicEntry {
    work_report: WorkReport,                  // w
    timeslot: u32,                            // t; N_T
    credential: Vec<(u16, Ed25519Signature)>, // a; (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
}

impl Encode for GuaranteeExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.timeslot.size_hint()
            + self.work_report.size_hint()
            + size_hint_length_discriminated_field(&self.credential)
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.timeslot.encode_to(dest); // TODO: check what `c` of `E_G` means (GP v0.3.0)
        self.work_report.encode_to(dest);
        encode_length_discriminated_field(&self.credential, dest);
    }
}

struct AssuranceExtrinsicEntry {
    anchor_parent_hash: Hash32,    // a
    assuring_cores_bitvec: BitVec, // f
    validator_index: u16,          // v; N_V
    signature: Ed25519Signature,   // s
}

impl Encode for AssuranceExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.anchor_parent_hash.size_hint()
            + Compact(self.assuring_cores_bitvec.len() as u32).size_hint() // size hint for bit vector length
            + (self.assuring_cores_bitvec.len() + 7) / 8 // size hint for packed bits in bytes
            + self.validator_index.size_hint()
            + self.signature.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.anchor_parent_hash.encode_to(dest);

        // Encode the bit vector length as a compact integer
        let bit_length = self.assuring_cores_bitvec.len() as u32;
        Compact(bit_length).encode_to(dest);

        // Encode the bit vector as Octets (packing)
        let mut byte = 0u8;
        for (i, bit) in self.assuring_cores_bitvec.iter().enumerate() {
            if bit {
                byte |= 1 << (i % 8);
            }
            if i % 8 == 7 {
                byte.encode_to(dest);
                byte = 0;
            }
        }
        // Encode any remaining bits in the final byte
        if self.assuring_cores_bitvec.len() % 8 != 0 {
            byte.encode_to(dest);
        }

        self.validator_index.encode_to(dest); // TODO: check if this should take the first 2 bytes only
        self.signature.encode_to(dest);
    }
}

struct PreimageLookupExtrinsicEntry {
    service_index: u32, // N_S
    preimage_data: Octets,
}

impl Encode for PreimageLookupExtrinsicEntry {
    fn size_hint(&self) -> usize {
        self.service_index.size_hint() + size_hint_length_discriminated_field(&self.preimage_data)
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.service_index.encode_to(dest);
        encode_length_discriminated_field(&self.preimage_data, dest);
    }
}

struct VerdictsExtrinsic {
    verdicts: Vec<Verdict>, // j
    culprits: Vec<Culprit>, // c
    faults: Vec<Fault>,     // f
}

impl Encode for VerdictsExtrinsic {
    fn size_hint(&self) -> usize {
        size_hint_length_discriminated_field(&self.verdicts)
            + size_hint_length_discriminated_field(&self.culprits)
            + size_hint_length_discriminated_field(&self.faults)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        encode_length_discriminated_field(&self.verdicts, dest);
        encode_length_discriminated_field(&self.culprits, dest);
        encode_length_discriminated_field(&self.faults, dest);
    }
}

struct Verdict {
    report_hash: Hash32,                                 // r
    epoch_index: u32,                                    // a
    votes: [Vote; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1], // v
}

impl Encode for Verdict {
    fn size_hint(&self) -> usize {
        self.report_hash.size_hint() + self.epoch_index.size_hint() + self.votes.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.report_hash.encode_to(dest);
        self.epoch_index.encode_to(dest);
        self.votes.encode_to(dest);
    }
}

struct Vote {
    is_report_valid: bool,
    voter_index: u16, // N_V
    voter_signature: Ed25519SignatureWithKeyAndMessage,
}

impl Encode for Vote {
    fn size_hint(&self) -> usize {
        self.is_report_valid.size_hint()
            + self.voter_index.size_hint()
            + self.voter_signature.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.is_report_valid.encode_to(dest);
        self.voter_index.encode_to(dest);
        self.voter_signature.encode_to(dest);
    }
}

#[derive(Encode)]
struct Culprit {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}

#[derive(Encode)]
struct Fault {
    report_hash: Hash32,
    validator_key: Ed25519PubKey,
    signature: Ed25519SignatureWithKeyAndMessage,
}
