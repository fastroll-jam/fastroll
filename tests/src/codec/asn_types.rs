use crate::asn_types::{
    BandersnatchKey, BandersnatchRingSignature, BandersnatchVrfSignature, ByteSequence, Ed25519Key,
    Ed25519Signature, OpaqueHash, TimeSlot,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RefineContext {
    pub anchor: OpaqueHash,
    pub state_root: OpaqueHash,
    pub beefy_root: OpaqueHash,
    pub lookup_anchor: OpaqueHash,
    pub lookup_anchor_slot: TimeSlot,
    pub prerequisite: Option<OpaqueHash>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImportSpec {
    pub tree_root: OpaqueHash,
    pub index: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExtrinsicSpec {
    pub hash: OpaqueHash,
    pub len: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Authorizer {
    pub code_hash: OpaqueHash,
    pub params: ByteSequence,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkItem {
    pub service: u32,
    pub code_hash: OpaqueHash,
    pub payload: ByteSequence,
    pub gas_limit: u64,
    pub import_segments: Vec<ImportSpec>,
    pub extrinsic: Vec<ExtrinsicSpec>,
    pub export_count: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnWorkPackage {
    pub authorization: ByteSequence,
    pub auth_code_host: u32,
    pub authorizer: Authorizer,
    pub context: RefineContext,
    pub items: Vec<WorkItem>,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WorkExecResult {
    ok(ByteSequence),
    out_of_gas,
    panic,
    bad_code,
    code_oversize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkResult {
    pub service: u32,
    pub code_hash: OpaqueHash,
    pub payload_hash: OpaqueHash,
    pub gas_ratio: u64,
    pub result: WorkExecResult,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkPackageSpec {
    pub hash: OpaqueHash,
    pub len: u32,
    pub erasure_root: OpaqueHash,
    pub exports_root: OpaqueHash,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WorkReport {
    pub package_spec: WorkPackageSpec,
    pub context: RefineContext,
    pub core_index: u16,
    pub authorizer_hash: OpaqueHash,
    pub auth_output: ByteSequence,
    // FIXME: add segments roots lookup dictionary
    pub results: Vec<WorkResult>, // SIZE(1..4)
}

// TODO: reuse from other test ASN types (e.g., Safrole)

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EpochMark {
    pub entropy: OpaqueHash,
    pub validators: Vec<BandersnatchKey>, // SIZE(validators-count)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TicketBody {
    pub id: OpaqueHash,
    pub attempt: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnHeader {
    pub parent: OpaqueHash,
    pub parent_state_root: OpaqueHash,
    pub extrinsic_hash: OpaqueHash,
    pub slot: u32,
    pub epoch_mark: Option<EpochMark>,
    pub tickets_mark: Option<Vec<TicketBody>>,
    pub offenders_mark: Vec<Ed25519Key>,
    pub author_index: u16,
    pub entropy_source: BandersnatchVrfSignature,
    pub seal: BandersnatchVrfSignature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TicketEnvelope {
    pub attempt: u8,
    pub signature: BandersnatchRingSignature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]

pub struct Judgement {
    pub vote: bool,
    pub index: u16,
    pub signature: Ed25519Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verdict {
    pub target: OpaqueHash,
    pub age: u32,
    pub votes: Vec<Judgement>, // SIZE(validators-super-majority)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Culprit {
    pub target: OpaqueHash,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fault {
    pub target: OpaqueHash,
    pub vote: bool,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnDisputesExtrinsic {
    pub verdicts: Vec<Verdict>,
    pub culprits: Vec<Culprit>,
    pub faults: Vec<Fault>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Preimage {
    pub requester: u32,
    pub blob: ByteSequence,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AvailAssurance {
    pub anchor: OpaqueHash,
    pub bitfield: ByteSequence, // SIZE(AVAIL_BITFIELD_BYTES)
    pub validator_index: u16,
    pub signature: Ed25519Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidatorSignature {
    pub validator_index: u16,
    pub signature: Ed25519Signature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReportGuarantee {
    pub report: WorkReport,
    pub slot: u32,
    pub signatures: Vec<ValidatorSignature>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnExtrinsic {
    pub tickets: Vec<TicketEnvelope>,
    pub disputes: AsnDisputesExtrinsic,
    pub preimages: Vec<Preimage>,
    pub assurances: Vec<AvailAssurance>,
    pub guarantees: Vec<ReportGuarantee>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnBlock {
    pub header: AsnHeader,
    pub extrinsic: AsnExtrinsic,
}
