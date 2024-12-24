use crate::test_utils::{
    deserialize_hex_array, deserialize_hex_vec, serialize_hex_array, serialize_hex_vec,
};
use bit_vec::BitVec;
use rjam_common::{
    BandersnatchPubKey, ByteArray, ByteSequence, Hash32, Octets, Ticket, ValidatorKey,
    ValidatorKeySet, FLOOR_TWO_THIRDS_VALIDATOR_COUNT, VALIDATOR_COUNT,
};
use rjam_crypto::Hasher;
use rjam_merkle::mmr::MerkleMountainRange;
use rjam_types::{
    block::{
        header::{BlockHeader, EpochMarker},
        Block,
    },
    common::workloads::{
        Authorizer, AvailabilitySpecs, ExtrinsicInfo, ImportInfo, RefinementContext,
        SegmentRootLookupTable,
        WorkExecutionError::{Bad, Big, OutOfGas, Panic},
        WorkExecutionOutput, WorkItem, WorkItemResult, WorkPackage, WorkPackageId, WorkReport,
    },
    extrinsics::{
        assurances::{AssurancesExtrinsic, AssurancesExtrinsicEntry},
        disputes::{Culprit, DisputesExtrinsic, Fault, Judgment, OffendersHeaderMarker, Verdict},
        guarantees::{GuaranteesCredential, GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
        preimages::{PreimageLookupsExtrinsic, PreimageLookupsExtrinsicEntry},
        tickets::{TicketsExtrinsic, TicketsExtrinsicEntry},
        Extrinsics,
    },
    state::{
        BlockHistoryEntry, DisputesState, PendingReport, PendingReports, ReportedWorkPackage,
        SlotSealerType, Timeslot,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    fmt::{Debug, Display},
    ops::Deref,
};
// ----------------------------------------------------
// -- Constants
// ----------------------------------------------------

pub const VALIDATORS_COUNT: usize = 6;
pub const VALIDATORS_SUPER_MAJORITY: usize = 5;
pub const EPOCH_LENGTH: usize = 12;
pub const CORE_COUNT: usize = 2;
// pub const AVAIL_BITFIELD_BYTES: usize = 1; // (CORE_COUNT + 7) / 8

// ----------------------------------------------------
// -- Simple Types
// ----------------------------------------------------

pub type TimeSlot = u32;
pub type OpaqueHash = ByteArray32;
pub type BandersnatchKey = ByteArray32;
pub type Ed25519Key = ByteArray32;
pub type Ed25519Signature = ByteArray64;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BandersnatchVrfSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 96],
);

impl From<ByteArray<96>> for BandersnatchVrfSignature {
    fn from(value: ByteArray<96>) -> Self {
        Self(value.0)
    }
}

impl Debug for BandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BandersnatchRingSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 784],
);

impl From<ByteArray<784>> for BandersnatchRingSignature {
    fn from(value: ByteArray<784>) -> Self {
        Self(value.0)
    }
}

impl Debug for BandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BlsKey(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 144],
);

impl From<ByteArray<144>> for BlsKey {
    fn from(value: ByteArray<144>) -> Self {
        Self(value.0)
    }
}

impl Debug for BlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AsnByteSequence(
    #[serde(
        serialize_with = "serialize_hex_vec",
        deserialize_with = "deserialize_hex_vec"
    )]
    pub Vec<u8>,
);

impl Debug for AsnByteSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Display for AsnByteSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Vec<u8>> for AsnByteSequence {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
pub struct ByteArray32(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 32],
);

impl From<ByteArray<32>> for ByteArray32 {
    fn from(value: ByteArray<32>) -> Self {
        Self(value.0)
    }
}

impl From<[u8; 32]> for ByteArray32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Debug for ByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for ByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct ByteArray64(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 64],
);

impl From<ByteArray<64>> for ByteArray64 {
    fn from(value: ByteArray<64>) -> Self {
        Self(value.0)
    }
}

impl Debug for ByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for ByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ----------------------------------------------------
// -- Application Specific Core
// ----------------------------------------------------

pub type ValidatorsData = [ValidatorData; VALIDATORS_COUNT];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidatorData {
    pub bandersnatch: BandersnatchKey,
    pub ed25519: Ed25519Key,
    pub bls: BlsKey,
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub metadata: [u8; 128],
}

impl Default for ValidatorData {
    fn default() -> Self {
        Self {
            bandersnatch: ByteArray32::default(),
            ed25519: ByteArray32::default(),
            bls: BlsKey([0u8; 144]),
            metadata: [0u8; 128],
        }
    }
}

impl From<ValidatorKey> for ValidatorData {
    fn from(value: ValidatorKey) -> Self {
        Self {
            bandersnatch: ByteArray32(value.bandersnatch_key.0),
            ed25519: ByteArray32(value.ed25519_key.0),
            bls: BlsKey(value.bls_key.0),
            metadata: value.metadata.0,
        }
    }
}

impl From<ValidatorData> for ValidatorKey {
    fn from(value: ValidatorData) -> Self {
        Self {
            bandersnatch_key: ByteArray::new(value.bandersnatch.0),
            ed25519_key: ByteArray::new(value.ed25519.0),
            bls_key: ByteArray::new(value.bls.0),
            metadata: ByteArray::new(value.metadata),
        }
    }
}

pub fn validators_data_to_validator_set(data: &ValidatorsData) -> ValidatorKeySet {
    let mut validator_keys = [ValidatorKey::default(); VALIDATOR_COUNT];
    for (i, validator_data) in data.iter().enumerate() {
        validator_keys[i] = ValidatorKey::from(validator_data.clone());
    }

    Box::new(validator_keys)
}

pub fn validator_set_to_validators_data(data: &ValidatorKeySet) -> ValidatorsData {
    let mut validators_data = ValidatorsData::default();
    for (i, key) in data.into_iter().enumerate() {
        validators_data[i] = ValidatorData::from(key);
    }

    validators_data
}

// ----------------------------------------------------
// -- Availability Assignments
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AvailabilityAssignment {
    pub report: AsnWorkReport,
    pub timeout: u32,
}

impl From<PendingReport> for AvailabilityAssignment {
    fn from(value: PendingReport) -> Self {
        Self {
            report: value.work_report.into(),
            timeout: value.timeslot.0,
        }
    }
}

impl From<AvailabilityAssignment> for PendingReport {
    fn from(value: AvailabilityAssignment) -> Self {
        Self {
            work_report: value.report.into(),
            timeslot: Timeslot::new(value.timeout),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AvailabilityAssignments([Option<AvailabilityAssignment>; CORE_COUNT]);

impl From<AvailabilityAssignments> for PendingReports {
    fn from(value: AvailabilityAssignments) -> Self {
        let mut reports: [Option<PendingReport>; CORE_COUNT] = Default::default();

        for (i, item) in value.0.iter().enumerate() {
            reports[i] = match item {
                Some(assignment) => {
                    let work_report = assignment.clone().report.into();
                    let pending_report = PendingReport {
                        work_report,
                        timeslot: Timeslot::new(assignment.timeout),
                    };
                    Some(pending_report)
                }
                None => None,
            };
        }

        PendingReports(Box::new(reports))
    }
}

impl From<PendingReports> for AvailabilityAssignments {
    fn from(value: PendingReports) -> Self {
        let mut assignments: [Option<AvailabilityAssignment>; CORE_COUNT] = Default::default();

        for (i, report_option) in value.0.iter().enumerate() {
            assignments[i] = match report_option {
                Some(pending_report) => {
                    let report = pending_report.clone().work_report.into();
                    let assignment = AvailabilityAssignment {
                        report,
                        timeout: pending_report.timeslot.0,
                    };
                    Some(assignment)
                }
                None => None,
            };
        }

        AvailabilityAssignments(assignments)
    }
}

// ----------------------------------------------------
// -- Refine Context
// ----------------------------------------------------

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

// ----------------------------------------------------
// -- Authorizations
// ----------------------------------------------------

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

// ----------------------------------------------------
// -- Work Package
// ----------------------------------------------------

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
pub struct AsnWorkItem {
    pub service: u32,
    pub code_hash: OpaqueHash,
    pub payload: AsnByteSequence,
    pub refine_gas_limit: u64,
    pub accumulate_gas_limit: u64,
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
            refine_gas_limit: value.refine_gas_limit,
            accumulate_gas_limit: value.accumulate_gas_limit,
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

// ----------------------------------------------------
// -- Work Report
// ----------------------------------------------------

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
            WorkExecResult::panic => Self::Error(Panic),
            WorkExecResult::bad_code => Self::Error(Bad),
            WorkExecResult::code_oversize => Self::Error(Big),
        }
    }
}

impl From<WorkExecutionOutput> for WorkExecResult {
    fn from(value: WorkExecutionOutput) -> Self {
        match value {
            WorkExecutionOutput::Output(bytes) => Self::ok(AsnByteSequence(bytes.0)),
            WorkExecutionOutput::Error(OutOfGas) => Self::out_of_gas,
            WorkExecutionOutput::Error(Panic) => Self::panic,
            WorkExecutionOutput::Error(Bad) => Self::bad_code,
            WorkExecutionOutput::Error(Big) => Self::code_oversize,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WorkResult {
    pub service_id: u32,
    pub code_hash: OpaqueHash,
    pub payload_hash: OpaqueHash,
    pub accumulate_gas: u64,
    pub result: WorkExecResult,
}

impl From<WorkResult> for WorkItemResult {
    fn from(value: WorkResult) -> Self {
        Self {
            service_index: value.service_id,
            service_code_hash: ByteArray::new(value.code_hash.0),
            payload_hash: ByteArray::new(value.payload_hash.0),
            gas_prioritization_ratio: value.accumulate_gas,
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
            accumulate_gas: value.gas_prioritization_ratio,
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

// ----------------------------------------------------
// -- Block History
// ----------------------------------------------------

pub type MmrPeak = Option<OpaqueHash>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Mmr {
    peaks: Vec<MmrPeak>,
}

impl<H: Hasher> From<Mmr> for MerkleMountainRange<H> {
    fn from(value: Mmr) -> Self {
        let peaks = value
            .peaks
            .into_iter()
            .map(|peak| peak.map(|hash| ByteArray::new(hash.0)))
            .collect();

        MerkleMountainRange::new_from_peaks(peaks)
    }
}

impl<H: Hasher> From<MerkleMountainRange<H>> for Mmr {
    fn from(value: MerkleMountainRange<H>) -> Self {
        let peaks = value
            .peaks
            .into_iter()
            .map(|peak| peak.map(|hash| ByteArray32(hash.0)))
            .collect();

        Mmr { peaks }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Reported {
    pub hash: OpaqueHash,
    pub exports_root: OpaqueHash,
}

pub type Reports = Vec<Reported>;

// Recorded disputes sequences and offenders
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlockInfo {
    header_hash: OpaqueHash,
    mmr: Mmr,
    state_root: OpaqueHash,
    reported: Reports,
}

impl From<BlockInfo> for BlockHistoryEntry {
    fn from(value: BlockInfo) -> Self {
        Self {
            header_hash: ByteArray::new(value.header_hash.0),
            accumulation_result_mmr: value.mmr.into(),
            state_root: ByteArray::new(value.state_root.0),
            reported_packages: value
                .reported
                .into_iter()
                .map(|reported| ReportedWorkPackage {
                    work_package_hash: ByteArray::new(reported.hash.0),
                    segment_root: ByteArray::new(reported.exports_root.0),
                })
                .collect(),
        }
    }
}

impl From<BlockHistoryEntry> for BlockInfo {
    fn from(value: BlockHistoryEntry) -> Self {
        Self {
            header_hash: ByteArray32(value.header_hash.0),
            mmr: value.accumulation_result_mmr.into(),
            state_root: ByteArray32(value.state_root.0),
            reported: value
                .reported_packages
                .into_iter()
                .map(|package| Reported {
                    hash: ByteArray32(package.work_package_hash.0),
                    exports_root: ByteArray32(package.segment_root.0),
                })
                .collect(),
        }
    }
}

// ----------------------------------------------------
// -- Tickets
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy, PartialEq)]
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

impl From<Ticket> for TicketBody {
    fn from(ticket: Ticket) -> Self {
        TicketBody {
            id: ByteArray32(ticket.id.0),
            attempt: ticket.attempt,
        }
    }
}

pub type TicketsBodies = [TicketBody; EPOCH_LENGTH];
pub type EpochKeys = [BandersnatchKey; EPOCH_LENGTH];

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
                        id: ByteArray::new(ticket_body.id.0),
                        attempt: ticket_body.attempt,
                    };
                }
                SlotSealerType::Tickets(Box::new(tickets))
            }
            TicketsOrKeys::keys(epoch_keys) => {
                let mut keys: [BandersnatchPubKey; EPOCH_LENGTH] = Default::default();
                for (i, key) in epoch_keys.into_iter().enumerate() {
                    keys[i] = ByteArray::new(key.0)
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
                        id: ByteArray32(ticket.id.0),
                        attempt: ticket.attempt,
                    };
                }
                TicketsOrKeys::tickets(ticket_bodies)
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                let mut epoch_keys: EpochKeys = Default::default();
                for (i, key) in keys.into_iter().enumerate() {
                    epoch_keys[i] = ByteArray32(key.0);
                }
                TicketsOrKeys::keys(epoch_keys)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

// ----------------------------------------------------
// -- Disputes
// ----------------------------------------------------

pub type WorkReportHash = ByteArray32;
pub type EpochIndex = u32;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeJudgement {
    pub vote: bool,
    pub index: u16,
    pub signature: Ed25519Signature,
}

impl From<DisputeJudgement> for Judgment {
    fn from(value: DisputeJudgement) -> Self {
        Self {
            is_report_valid: value.vote,
            voter: value.index,
            voter_signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<Judgment> for DisputeJudgement {
    fn from(value: Judgment) -> Self {
        Self {
            vote: value.is_report_valid,
            index: value.voter,
            signature: ByteArray64(value.voter_signature.0),
        }
    }
}

pub type DisputeJudgements = [DisputeJudgement; VALIDATORS_SUPER_MAJORITY];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeVerdict {
    pub target: WorkReportHash,
    pub age: EpochIndex,
    pub votes: DisputeJudgements,
}

impl From<DisputeVerdict> for Verdict {
    fn from(value: DisputeVerdict) -> Self {
        let mut judgments: [Judgment; FLOOR_TWO_THIRDS_VALIDATOR_COUNT + 1] = Default::default();

        for (i, vote) in value.votes.into_iter().enumerate() {
            judgments[i] = vote.into()
        }

        Self {
            report_hash: ByteArray::new(value.target.0),
            epoch_index: value.age,
            judgments: Box::new(judgments),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeCulpritProof {
    pub target: WorkReportHash,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

impl From<DisputeCulpritProof> for Culprit {
    fn from(value: DisputeCulpritProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisputeFaultProof {
    pub target: WorkReportHash,
    pub vote: bool,
    pub key: Ed25519Key,
    pub signature: Ed25519Signature,
}

impl From<DisputeFaultProof> for Fault {
    fn from(value: DisputeFaultProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            is_report_valid: value.vote,
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DisputesOutputMarks {
    pub offenders_mark: Vec<Ed25519Key>,
}

impl From<OffendersHeaderMarker> for DisputesOutputMarks {
    fn from(value: OffendersHeaderMarker) -> Self {
        let offenders_mark = value.items.into_iter().map(ByteArray32::from).collect();
        Self { offenders_mark }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DisputesRecords {
    pub good: Vec<WorkReportHash>,  // Good verdicts
    pub bad: Vec<WorkReportHash>,   // Bad verdicts
    pub wonky: Vec<WorkReportHash>, // Wonky verdicts
    pub offenders: Vec<Ed25519Key>, // Offenders
}

impl From<DisputesRecords> for DisputesState {
    fn from(value: DisputesRecords) -> Self {
        Self {
            good_set: value
                .good
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            bad_set: value
                .bad
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            wonky_set: value
                .wonky
                .into_iter()
                .map(|hash| ByteArray::new(hash.0))
                .collect(),
            punish_set: value
                .offenders
                .into_iter()
                .map(|key| ByteArray::new(key.0))
                .collect(),
        }
    }
}

impl From<DisputesState> for DisputesRecords {
    fn from(value: DisputesState) -> Self {
        Self {
            good: value.good_set.into_iter().map(ByteArray32::from).collect(),
            bad: value.bad_set.into_iter().map(ByteArray32::from).collect(),
            wonky: value.wonky_set.into_iter().map(ByteArray32::from).collect(),
            offenders: value
                .punish_set
                .into_iter()
                .map(ByteArray32::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnDisputesExtrinsic {
    pub verdicts: Vec<DisputeVerdict>,
    pub culprits: Vec<DisputeCulpritProof>,
    pub faults: Vec<DisputeFaultProof>,
}

impl From<AsnDisputesExtrinsic> for DisputesExtrinsic {
    fn from(value: AsnDisputesExtrinsic) -> Self {
        Self {
            verdicts: value.verdicts.into_iter().map(Verdict::from).collect(),
            culprits: value.culprits.into_iter().map(Culprit::from).collect(),
            faults: value.faults.into_iter().map(Fault::from).collect(),
        }
    }
}

// ----------------------------------------------------
// -- Preimages
// ----------------------------------------------------

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

// ----------------------------------------------------
// -- Assurances
// ----------------------------------------------------

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

// ----------------------------------------------------
// -- Guarantees
// ----------------------------------------------------

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

// ----------------------------------------------------
// -- Header
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EpochMark {
    pub entropy: OpaqueHash,
    pub tickets_entropy: OpaqueHash,
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
            tickets_entropy: ByteArray::new(value.tickets_entropy.0),
            validators: Box::new(validators_array),
        }
    }
}

impl From<EpochMarker> for EpochMark {
    fn from(marker: EpochMarker) -> Self {
        EpochMark {
            entropy: ByteArray32(marker.entropy.0),
            tickets_entropy: ByteArray32(marker.tickets_entropy.0),
            validators: marker
                .validators
                .into_iter()
                .map(ByteArray32::from)
                .collect(),
        }
    }
}

pub type TicketsMark = [TicketBody; EPOCH_LENGTH];

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

// ----------------------------------------------------
// -- Header
// ----------------------------------------------------

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
