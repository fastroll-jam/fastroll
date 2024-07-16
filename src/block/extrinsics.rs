use crate::common::{
    BandersnatchRingVrfProof, Ed25519PubKey, Ed25519Signature, Ed25519SignatureWithKeyAndMessage,
    Hash32, Octet, WorkReport, FLOOR_TWO_THIRDS_VALIDATOR_COUNT,
};
use bit_vec::BitVec;

type TicketsExtrinsic = Vec<(u32, BandersnatchRingVrfProof)>; // (N_N, [u8; 784])
type GuaranteesExtrinsic = Vec<(WorkReport, u32, Vec<(u32, Ed25519Signature)>)>; // (WorkReport, N_T, [(N_V, Ed25519Signature)]_{2:3}; length up to CORE_COUNT
type AssurancesExtrinsic = Vec<(Hash32, BitVec, u32, Ed25519Signature)>; // length up to VALIDATOR_COUNT
type PreimageLookupExtrinsic = Vec<(u32, Octet)>;
type JudgementsExtrinsic = (
    Vec<(
        Hash32,
        u32,
        [(bool, u32, Ed25519Signature); FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1],
    )>, // votes
    Vec<(Hash32, Ed25519PubKey, Ed25519SignatureWithKeyAndMessage)>, // culprits
    Vec<(Hash32, Ed25519PubKey, Ed25519SignatureWithKeyAndMessage)>, // faults
);

pub struct Extrinsics {
    tickets_extrinsic: TicketsExtrinsic,
    guarantees_extrinsic: GuaranteesExtrinsic,
    assurances_extrinsic: AssurancesExtrinsic,
    preimage_lookup_extrinsic: PreimageLookupExtrinsic,
    judgements_extrinsic: JudgementsExtrinsic,
}
