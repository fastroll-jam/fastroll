use crate::{asn_types::*, disputes::asn_types::DisputesXt};
use bit_vec::BitVec;
use rjam_common::{ByteArray, ByteSequence, Hash32, Octets, Ticket, VALIDATOR_COUNT};
use rjam_types::{
    block::{
        header::{BlockHeader, EpochMarker},
        Block,
    },
    common::workloads::{
        Authorizer, AvailabilitySpecs, ExtrinsicInfo, ImportInfo, RefinementContext,
        SegmentRootLookupTable,
        WorkExecutionError::{
            CodeSizeExceeded, OutOfGas, ServiceCodeLookupError, UnexpectedTermination,
        },
        WorkExecutionOutput, WorkItem, WorkItemResult, WorkPackage, WorkPackageId, WorkReport,
    },
    extrinsics::{
        assurances::{AssurancesExtrinsic, AssurancesExtrinsicEntry},
        guarantees::{GuaranteesCredential, GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
        preimages::{PreimageLookupsExtrinsic, PreimageLookupsExtrinsicEntry},
        tickets::{TicketsExtrinsic, TicketsExtrinsicEntry},
        Extrinsics,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Deref};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RefineContext {
    pub anchor: OpaqueHash,
    pub state_root: OpaqueHash,
    pub beefy_root: OpaqueHash,
    pub lookup_anchor: OpaqueHash,
    pub lookup_anchor_slot: TimeSlot,
    pub prerequisites: Vec<OpaqueHash>,
}

impl From<RefineContext> for RefinementContext {
    fn from(value: RefineContext) -> Self {
        Self {
            anchor_header_hash: ByteArray::new(value.anchor.0),
            anchor_state_root: ByteArray::new(value.state_root.0),
            beefy_root: ByteArray::new(value.beefy_root.0),
            lookup_anchor_header_hash: ByteArray::new(value.lookup_anchor.0),
            lookup_anchor_timeslot: value.lookup_anchor_slot,
            prerequisite_work_packages: value
                .prerequisites
                .into_iter()
                .map(|h| ByteArray::new(h.0))
                .collect(),
        }
    }
}

impl From<RefinementContext> for RefineContext {
    fn from(value: RefinementContext) -> Self {
        Self {
            anchor: ByteArray32(value.anchor_header_hash.0),
            state_root: ByteArray32(value.anchor_state_root.0),
            beefy_root: ByteArray32(value.beefy_root.0),
            lookup_anchor: ByteArray32(value.lookup_anchor_header_hash.0),
            lookup_anchor_slot: value.lookup_anchor_timeslot,
            prerequisites: value
                .prerequisite_work_packages
                .into_iter()
                .map(|h| ByteArray32(h.0))
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImportSpec {
    pub tree_root: OpaqueHash,
    pub index: u16,
}

impl From<ImportSpec> for ImportInfo {
    fn from(value: ImportSpec) -> Self {
        let hash = ByteArray::new(value.tree_root.0);
        let work_package_id = if value.index >= (1 << 15) {
            WorkPackageId::WorkPackageHash(hash)
        } else {
            WorkPackageId::SegmentRoot(hash)
        };

        Self {
            work_package_id,
            item_index: value.index,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExtrinsicSpec {
    pub hash: OpaqueHash,
    pub len: u32,
}

impl From<ExtrinsicSpec> for ExtrinsicInfo {
    fn from(value: ExtrinsicSpec) -> Self {
        Self {
            blob_hash: ByteArray::new(value.hash.0),
            blob_length: value.len as usize,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnAuthorizer {
    pub code_hash: OpaqueHash,
    pub params: AsnByteSequence,
}

impl From<AsnAuthorizer> for Authorizer {
    fn from(value: AsnAuthorizer) -> Self {
        Self {
            auth_code_hash: ByteArray::new(value.code_hash.0),
            param_blob: ByteSequence::from_vec(value.params.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnWorkItem {
    pub service: u32,
    pub code_hash: OpaqueHash,
    pub payload: AsnByteSequence,
    pub gas_limit: u64,
    pub import_segments: Vec<ImportSpec>,
    pub extrinsic: Vec<ExtrinsicSpec>,
    pub export_count: u16,
}

impl From<AsnWorkItem> for WorkItem {
    fn from(value: AsnWorkItem) -> Self {
        Self {
            service_index: value.service,
            service_code_hash: ByteArray::new(value.code_hash.0),
            payload_blob: ByteSequence::from_vec(value.payload.0),
            gas_limit: value.gas_limit,
            import_segment_ids: value
                .import_segments
                .into_iter()
                .map(ImportInfo::from)
                .collect(),
            extrinsic_data_info: value
                .extrinsic
                .into_iter()
                .map(ExtrinsicInfo::from)
                .collect(),
            export_segment_count: value.export_count as usize,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnWorkPackage {
    pub authorization: AsnByteSequence,
    pub auth_code_host: u32,
    pub authorizer: AsnAuthorizer,
    pub context: RefineContext,
    pub items: Vec<AsnWorkItem>,
}

impl From<AsnWorkPackage> for WorkPackage {
    fn from(value: AsnWorkPackage) -> Self {
        Self {
            auth_token: ByteSequence::from_vec(value.authorization.0),
            authorizer_address: value.auth_code_host,
            authorizer: value.authorizer.into(),
            context: value.context.into(),
            work_items: value.items.into_iter().map(WorkItem::from).collect(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum WorkExecResult {
    ok(AsnByteSequence),
    out_of_gas,
    panic,
    bad_code,
    code_oversize,
}

impl From<WorkExecResult> for WorkExecutionOutput {
    fn from(value: WorkExecResult) -> Self {
        match value {
            WorkExecResult::ok(bytes) => Self::Output(Octets::from_vec(bytes.0)),
            WorkExecResult::out_of_gas => Self::Error(OutOfGas),
            WorkExecResult::panic => Self::Error(UnexpectedTermination),
            WorkExecResult::bad_code => Self::Error(ServiceCodeLookupError),
            WorkExecResult::code_oversize => Self::Error(CodeSizeExceeded),
        }
    }
}

impl From<WorkExecutionOutput> for WorkExecResult {
    fn from(value: WorkExecutionOutput) -> Self {
        match value {
            WorkExecutionOutput::Output(bytes) => Self::ok(AsnByteSequence(bytes.0)),
            WorkExecutionOutput::Error(OutOfGas) => Self::out_of_gas,
            WorkExecutionOutput::Error(UnexpectedTermination) => Self::panic,
            WorkExecutionOutput::Error(ServiceCodeLookupError) => Self::bad_code,
            WorkExecutionOutput::Error(CodeSizeExceeded) => Self::code_oversize,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WorkResult {
    pub service_id: u32,
    pub code_hash: OpaqueHash,
    pub payload_hash: OpaqueHash,
    pub gas: u64,
    pub result: WorkExecResult,
}

impl From<WorkResult> for WorkItemResult {
    fn from(value: WorkResult) -> Self {
        Self {
            service_index: value.service_id,
            service_code_hash: ByteArray::new(value.code_hash.0),
            payload_hash: ByteArray::new(value.payload_hash.0),
            gas_prioritization_ratio: value.gas,
            refinement_output: value.result.into(),
        }
    }
}

impl From<WorkItemResult> for WorkResult {
    fn from(value: WorkItemResult) -> Self {
        Self {
            service_id: value.service_index,
            code_hash: ByteArray32(value.service_code_hash.0),
            payload_hash: ByteArray32(value.payload_hash.0),
            gas: value.gas_prioritization_ratio,
            result: value.refinement_output.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WorkPackageSpec {
    pub hash: OpaqueHash,
    pub length: u32,
    pub erasure_root: OpaqueHash,
    pub exports_root: OpaqueHash,
    pub exports_count: u16,
}

impl From<WorkPackageSpec> for AvailabilitySpecs {
    fn from(value: WorkPackageSpec) -> Self {
        Self {
            work_package_hash: ByteArray::new(value.hash.0),
            work_package_length: value.length,
            erasure_root: ByteArray::new(value.erasure_root.0),
            segment_root: ByteArray::new(value.exports_root.0),
            segment_count: value.exports_count as usize,
        }
    }
}

impl From<AvailabilitySpecs> for WorkPackageSpec {
    fn from(value: AvailabilitySpecs) -> Self {
        Self {
            hash: ByteArray32(value.work_package_hash.0),
            length: value.work_package_length,
            erasure_root: ByteArray32(value.erasure_root.0),
            exports_root: ByteArray32(value.segment_root.0),
            exports_count: value.segment_count as u16,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SegmentRootLookupItem {
    pub work_package_hash: OpaqueHash,
    pub segment_tree_root: OpaqueHash,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(transparent)]
pub struct AsnSegmentRootLookupTable {
    pub items: Vec<SegmentRootLookupItem>,
}

impl Deref for AsnSegmentRootLookupTable {
    type Target = Vec<SegmentRootLookupItem>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl From<AsnSegmentRootLookupTable> for SegmentRootLookupTable {
    fn from(value: AsnSegmentRootLookupTable) -> Self {
        let mut map: HashMap<Hash32, Hash32> = HashMap::with_capacity(value.len());

        for item in value.iter() {
            let map_key = ByteArray::new(item.work_package_hash.0);
            let map_value = ByteArray::new(item.segment_tree_root.0);
            map.insert(map_key, map_value);
        }

        Self::new(map)
    }
}

impl From<SegmentRootLookupTable> for AsnSegmentRootLookupTable {
    fn from(value: SegmentRootLookupTable) -> Self {
        let mut items: Vec<SegmentRootLookupItem> = Vec::with_capacity(value.len());
        for (key, value) in value.iter() {
            items.push(SegmentRootLookupItem {
                work_package_hash: ByteArray32(key.0),
                segment_tree_root: ByteArray32(value.0),
            })
        }

        AsnSegmentRootLookupTable { items }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnWorkReport {
    pub package_spec: WorkPackageSpec,
    pub context: RefineContext,
    pub core_index: u16,
    pub authorizer_hash: OpaqueHash,
    pub auth_output: AsnByteSequence,
    pub segment_root_lookup: AsnSegmentRootLookupTable,
    pub results: Vec<WorkResult>, // SIZE(1..4)
}

impl From<AsnWorkReport> for WorkReport {
    fn from(value: AsnWorkReport) -> Self {
        Self {
            specs: value.package_spec.into(),
            refinement_context: value.context.into(),
            core_index: value.core_index,
            authorizer_hash: ByteArray::new(value.authorizer_hash.0),
            authorization_output: ByteSequence::from_vec(value.auth_output.0),
            segment_roots_lookup: value.segment_root_lookup.into(),
            results: value
                .results
                .into_iter()
                .map(WorkItemResult::from)
                .collect(),
        }
    }
}

impl From<WorkReport> for AsnWorkReport {
    fn from(value: WorkReport) -> Self {
        Self {
            package_spec: value.specs.into(),
            context: value.refinement_context.into(),
            core_index: value.core_index,
            authorizer_hash: ByteArray32(value.authorizer_hash.0),
            auth_output: AsnByteSequence(value.authorization_output.0),
            segment_root_lookup: value.segment_roots_lookup.into(),
            results: value.results.into_iter().map(WorkResult::from).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EpochMark {
    pub entropy: OpaqueHash,
    pub validators: Vec<BandersnatchKey>, // SIZE(validators-count)
}

impl From<EpochMark> for EpochMarker {
    fn from(value: EpochMark) -> Self {
        let mut validators_array = [ByteArray::default(); VALIDATOR_COUNT];
        for (i, key) in value.validators.into_iter().enumerate() {
            validators_array[i] = ByteArray::new(key.0);
        }
        Self {
            entropy: ByteArray::new(value.entropy.0),
            validators: Box::new(validators_array),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TicketBody {
    pub attempt: u8,
    pub id: OpaqueHash,
}

impl From<TicketBody> for Ticket {
    fn from(value: TicketBody) -> Self {
        Self {
            attempt: value.attempt,
            id: ByteArray::new(value.id.0),
        }
    }
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

impl From<AsnHeader> for BlockHeader {
    fn from(value: AsnHeader) -> Self {
        Self {
            parent_hash: ByteArray::new(value.parent.0),
            parent_state_root: ByteArray::new(value.parent_state_root.0),
            extrinsic_hash: ByteArray::new(value.extrinsic_hash.0),
            timeslot_index: value.slot,
            epoch_marker: value.epoch_mark.map(EpochMarker::from),
            winning_tickets_marker: value.tickets_mark.map(|tickets| {
                let mut tickets_array = [Ticket::default(); EPOCH_LENGTH];
                for (i, ticket) in tickets.into_iter().enumerate() {
                    tickets_array[i] = ticket.into();
                }
                tickets_array
            }),
            offenders_marker: value
                .offenders_mark
                .into_iter()
                .map(|key| ByteArray::new(key.0))
                .collect(),
            block_author_index: value.author_index,
            vrf_signature: ByteArray::new(value.entropy_source.0),
            block_seal: ByteArray::new(value.seal.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TicketEnvelope {
    pub attempt: u8,
    pub signature: BandersnatchRingSignature,
}

impl From<TicketEnvelope> for TicketsExtrinsicEntry {
    fn from(value: TicketEnvelope) -> Self {
        Self {
            ticket_proof: Box::new(ByteArray::new(value.signature.0)),
            entry_index: value.attempt,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnTicketsExtrinsic(pub Vec<TicketEnvelope>);

impl From<AsnTicketsExtrinsic> for TicketsExtrinsic {
    fn from(value: AsnTicketsExtrinsic) -> Self {
        Self {
            items: value
                .0
                .into_iter()
                .map(TicketsExtrinsicEntry::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Preimage {
    pub requester: u32,
    pub blob: AsnByteSequence,
}

impl From<Preimage> for PreimageLookupsExtrinsicEntry {
    fn from(value: Preimage) -> Self {
        Self {
            service_index: value.requester,
            preimage_data: ByteSequence::from_vec(value.blob.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AvailAssurance {
    pub anchor: OpaqueHash,
    pub bitfield: AsnByteSequence, // SIZE(AVAIL_BITFIELD_BYTES)
    pub validator_index: u16,
    pub signature: Ed25519Signature,
}

// Example: 0x01 => 0b0000_0001 => (truncate num_bits) => 0b01 => BitVec([1, 0])
fn bytes_to_bitvec(bytes: &[u8], num_bits: usize) -> BitVec {
    let bitvec = BitVec::from_bytes(bytes);
    let mut bitvec_rev = BitVec::new();
    for bit in bitvec.iter().rev() {
        bitvec_rev.push(bit);
    }

    bitvec_rev.truncate(num_bits);
    bitvec_rev
}

impl From<AvailAssurance> for AssurancesExtrinsicEntry {
    fn from(value: AvailAssurance) -> Self {
        Self {
            anchor_parent_hash: ByteArray::new(value.anchor.0),
            assuring_cores_bitvec: bytes_to_bitvec(&value.bitfield.0, CORE_COUNT),
            validator_index: value.validator_index,
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidatorSignature {
    pub validator_index: u16,
    pub signature: Ed25519Signature,
}

impl From<ValidatorSignature> for GuaranteesCredential {
    fn from(value: ValidatorSignature) -> Self {
        Self {
            validator_index: value.validator_index,
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReportGuarantee {
    pub report: AsnWorkReport,
    pub slot: u32,
    pub signatures: Vec<ValidatorSignature>,
}

impl From<ReportGuarantee> for GuaranteesExtrinsicEntry {
    fn from(value: ReportGuarantee) -> Self {
        Self {
            work_report: value.report.into(),
            timeslot_index: value.slot,
            credentials: value
                .signatures
                .into_iter()
                .map(GuaranteesCredential::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnPreimageLookupsExtrinsic(pub Vec<Preimage>);

impl From<AsnPreimageLookupsExtrinsic> for PreimageLookupsExtrinsic {
    fn from(value: AsnPreimageLookupsExtrinsic) -> Self {
        Self {
            items: value
                .0
                .into_iter()
                .map(PreimageLookupsExtrinsicEntry::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnAssurancesExtrinsic(pub Vec<AvailAssurance>);

impl From<AsnAssurancesExtrinsic> for AssurancesExtrinsic {
    fn from(value: AsnAssurancesExtrinsic) -> Self {
        Self {
            items: value
                .0
                .into_iter()
                .map(AssurancesExtrinsicEntry::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnGuaranteesExtrinsic(pub Vec<ReportGuarantee>);

impl From<AsnGuaranteesExtrinsic> for GuaranteesExtrinsic {
    fn from(value: AsnGuaranteesExtrinsic) -> Self {
        Self {
            items: value
                .0
                .into_iter()
                .map(GuaranteesExtrinsicEntry::from)
                .collect(),
        }
    }
}

pub type AsnDisputesExtrinsic = DisputesXt;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnExtrinsic {
    pub tickets: AsnTicketsExtrinsic,
    pub disputes: AsnDisputesExtrinsic,
    pub preimages: AsnPreimageLookupsExtrinsic,
    pub assurances: AsnAssurancesExtrinsic,
    pub guarantees: AsnGuaranteesExtrinsic,
}

impl From<AsnExtrinsic> for Extrinsics {
    fn from(value: AsnExtrinsic) -> Self {
        Self {
            tickets: value.tickets.into(),
            disputes: value.disputes.into(),
            preimage_lookups: value.preimages.into(),
            assurances: value.assurances.into(),
            guarantees: value.guarantees.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnBlock {
    pub header: AsnHeader,
    pub extrinsic: AsnExtrinsic,
}

impl From<AsnBlock> for Block {
    fn from(value: AsnBlock) -> Self {
        Self {
            header: value.header.into(),
            extrinsics: value.extrinsic.into(),
        }
    }
}
