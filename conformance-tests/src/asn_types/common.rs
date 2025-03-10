#![allow(dead_code)]
use crate::serde_utils::{
    deserialize_hex_array, deserialize_hex_vec, serialize_hex_array, serialize_hex_vec,
};
use bit_vec::BitVec;
use rjam_common::{
    BandersnatchPubKey, ByteArray, ByteSequence, Hash32, Octets, Ticket, ValidatorKey,
    ValidatorKeySet, FLOOR_TWO_THIRDS_VALIDATOR_COUNT, MAX_AUTH_QUEUE_SIZE, VALIDATOR_COUNT,
};
use rjam_crypto::Hasher;
use rjam_merkle::mmr::MerkleMountainRange;
use rjam_types::{
    block::{
        header::{BlockHeader, EpochMarker},
        Block,
    },
    common::workloads::{
        Authorizer, AvailSpecs, ExtrinsicInfo, ImportInfo, RefinementContext,
        SegmentRootLookupTable,
        WorkExecutionError::{Bad, BadExports, Big, OutOfGas, Panic},
        WorkExecutionOutput, WorkItem, WorkItemResult, WorkPackage, WorkPackageId, WorkReport,
    },
    extrinsics::{
        assurances::{AssurancesXt, AssurancesXtEntry},
        disputes::{Culprit, DisputesXt, Fault, Judgment, OffendersHeaderMarker, Verdict},
        guarantees::{GuaranteesCredential, GuaranteesXt, GuaranteesXtEntry},
        preimages::{PreimagesXt, PreimagesXtEntry},
        tickets::{TicketsXt, TicketsXtEntry},
        Extrinsics,
    },
    state::{
        AuthPool, AuthQueue, BlockHistory, BlockHistoryEntry, DisputesState, EpochEntropy,
        EpochValidatorStats, PendingReport, PendingReports, ReportedWorkPackage, SlotSealerType,
        Timeslot, ValidatorStatEntry, ValidatorStats,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    array::from_fn,
    collections::HashMap,
    fmt,
    fmt::{Debug, Display},
    ops::Deref,
};
// ----------------------------------------------------
// -- Constants
// ----------------------------------------------------

pub const ASN_VALIDATORS_COUNT: usize = 6;
pub const ASN_VALIDATORS_SUPER_MAJORITY: usize = 5;
pub const ASN_EPOCH_LENGTH: usize = 12;
pub const ASN_CORE_COUNT: usize = 2;

// ----------------------------------------------------
// -- Simple Types
// ----------------------------------------------------

pub type AsnTimeSlot = u32;
pub type AsnCoreIndex = u16;
pub type AsnOpaqueHash = AsnByteArray32;
pub type AsnBandersnatchKey = AsnByteArray32;
pub type AsnEd25519Key = AsnByteArray32;
pub type AsnEd25519Signature = AsnByteArray64;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnBandersnatchRingRoot(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 144],
);

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AsnBandersnatchVrfSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 96],
);

impl From<ByteArray<96>> for AsnBandersnatchVrfSignature {
    fn from(value: ByteArray<96>) -> Self {
        Self(value.0)
    }
}

impl Debug for AsnBandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for AsnBandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AsnBandersnatchRingSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 784],
);

impl From<ByteArray<784>> for AsnBandersnatchRingSignature {
    fn from(value: ByteArray<784>) -> Self {
        Self(value.0)
    }
}

impl Debug for AsnBandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for AsnBandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct AsnBlsKey(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 144],
);

impl From<ByteArray<144>> for AsnBlsKey {
    fn from(value: ByteArray<144>) -> Self {
        Self(value.0)
    }
}

impl From<AsnBlsKey> for ByteArray<144> {
    fn from(value: AsnBlsKey) -> Self {
        Self(value.0)
    }
}

impl Debug for AsnBlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for AsnBlsKey {
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

impl From<ByteSequence> for AsnByteSequence {
    fn from(value: ByteSequence) -> Self {
        Self(value.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
pub struct AsnByteArray32(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 32],
);

impl From<ByteArray<32>> for AsnByteArray32 {
    fn from(value: ByteArray<32>) -> Self {
        Self(value.0)
    }
}

impl From<AsnByteArray32> for ByteArray<32> {
    fn from(value: AsnByteArray32) -> Self {
        Self(value.0)
    }
}

impl From<[u8; 32]> for AsnByteArray32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Debug for AsnByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for AsnByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct AsnByteArray64(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 64],
);

impl From<ByteArray<64>> for AsnByteArray64 {
    fn from(value: ByteArray<64>) -> Self {
        Self(value.0)
    }
}

impl From<AsnByteArray64> for ByteArray<64> {
    fn from(value: AsnByteArray64) -> Self {
        Self(value.0)
    }
}

impl Debug for AsnByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Default for AsnByteArray64 {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl Display for AsnByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ----------------------------------------------------
// -- Application Specific Core
// ----------------------------------------------------

pub type AsnValidatorIndex = u16;
pub type AsnGas = u64;
pub type AsnEntropy = AsnOpaqueHash;
pub type AsnHeaderHash = AsnOpaqueHash;
pub type AsnValidatorsData = [AsnValidatorData; ASN_VALIDATORS_COUNT];
pub type AsnWorkPackageHash = AsnOpaqueHash;
pub type AsnWorkReportHash = AsnOpaqueHash;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnEntropyBuffer(pub [AsnEntropy; 4]);

impl From<EpochEntropy> for AsnEntropyBuffer {
    fn from(value: EpochEntropy) -> Self {
        Self(value.0.map(|entropy| AsnByteArray32(entropy.0)))
    }
}

impl From<AsnEntropyBuffer> for EpochEntropy {
    fn from(value: AsnEntropyBuffer) -> Self {
        Self(value.0.map(|entropy| ByteArray::new(entropy.0)))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnValidatorData {
    pub bandersnatch: AsnBandersnatchKey,
    pub ed25519: AsnEd25519Key,
    pub bls: AsnBlsKey,
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub metadata: [u8; 128],
}

impl Default for AsnValidatorData {
    fn default() -> Self {
        Self {
            bandersnatch: AsnByteArray32::default(),
            ed25519: AsnByteArray32::default(),
            bls: AsnBlsKey([0u8; 144]),
            metadata: [0u8; 128],
        }
    }
}

impl From<ValidatorKey> for AsnValidatorData {
    fn from(value: ValidatorKey) -> Self {
        Self {
            bandersnatch: value.bandersnatch_key.into(),
            ed25519: value.ed25519_key.into(),
            bls: value.bls_key.into(),
            metadata: value.metadata.0,
        }
    }
}

impl From<AsnValidatorData> for ValidatorKey {
    fn from(value: AsnValidatorData) -> Self {
        Self {
            bandersnatch_key: value.bandersnatch.into(),
            ed25519_key: value.ed25519.into(),
            bls_key: value.bls.into(),
            metadata: ByteArray::new(value.metadata),
        }
    }
}

pub fn validators_data_to_validator_set(data: &AsnValidatorsData) -> ValidatorKeySet {
    let mut validator_keys = [ValidatorKey::default(); VALIDATOR_COUNT];
    for (i, validator_data) in data.iter().enumerate() {
        validator_keys[i] = ValidatorKey::from(validator_data.clone());
    }

    Box::new(validator_keys)
}

pub fn validator_set_to_validators_data(data: &ValidatorKeySet) -> AsnValidatorsData {
    let mut validators_data = AsnValidatorsData::default();
    for (i, key) in data.into_iter().enumerate() {
        validators_data[i] = AsnValidatorData::from(key);
    }

    validators_data
}

// ----------------------------------------------------
// -- Service
// ----------------------------------------------------

pub type AsnServiceId = u32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnServiceInfo {
    pub code_hash: AsnOpaqueHash,
    pub balance: u64,
    pub min_item_gas: AsnGas,
    pub min_memo_gas: AsnGas,
    pub bytes: u64,
    pub items: u32,
}

// ----------------------------------------------------
// -- Availability Assignments
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAvailAssignment {
    pub report: AsnWorkReport,
    pub timeout: u32,
}

impl From<PendingReport> for AsnAvailAssignment {
    fn from(value: PendingReport) -> Self {
        Self {
            report: value.work_report.into(),
            timeout: value.reported_timeslot.0,
        }
    }
}

impl From<AsnAvailAssignment> for PendingReport {
    fn from(value: AsnAvailAssignment) -> Self {
        Self {
            work_report: value.report.into(),
            reported_timeslot: Timeslot::new(value.timeout),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnAvailAssignments([Option<AsnAvailAssignment>; ASN_CORE_COUNT]);

impl From<AsnAvailAssignments> for PendingReports {
    fn from(value: AsnAvailAssignments) -> Self {
        let mut reports: [Option<PendingReport>; ASN_CORE_COUNT] = Default::default();

        for (i, item) in value.0.iter().enumerate() {
            reports[i] = match item {
                Some(assignment) => {
                    let work_report = assignment.clone().report.into();
                    let pending_report = PendingReport {
                        work_report,
                        reported_timeslot: Timeslot::new(assignment.timeout),
                    };
                    Some(pending_report)
                }
                None => None,
            };
        }

        PendingReports(Box::new(reports))
    }
}

impl From<PendingReports> for AsnAvailAssignments {
    fn from(value: PendingReports) -> Self {
        let mut assignments: [Option<AsnAvailAssignment>; ASN_CORE_COUNT] = Default::default();

        for (i, report_option) in value.0.iter().enumerate() {
            assignments[i] = match report_option {
                Some(pending_report) => {
                    let report = pending_report.clone().work_report.into();
                    let assignment = AsnAvailAssignment {
                        report,
                        timeout: pending_report.reported_timeslot.0,
                    };
                    Some(assignment)
                }
                None => None,
            };
        }

        AsnAvailAssignments(assignments)
    }
}

// ----------------------------------------------------
// -- Refine Context
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnRefineContext {
    pub anchor: AsnOpaqueHash,
    pub state_root: AsnOpaqueHash,
    pub beefy_root: AsnOpaqueHash,
    pub lookup_anchor: AsnOpaqueHash,
    pub lookup_anchor_slot: AsnTimeSlot,
    pub prerequisites: Vec<AsnOpaqueHash>,
}

impl From<AsnRefineContext> for RefinementContext {
    fn from(value: AsnRefineContext) -> Self {
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

impl From<RefinementContext> for AsnRefineContext {
    fn from(value: RefinementContext) -> Self {
        Self {
            anchor: AsnByteArray32(value.anchor_header_hash.0),
            state_root: AsnByteArray32(value.anchor_state_root.0),
            beefy_root: AsnByteArray32(value.beefy_root.0),
            lookup_anchor: AsnByteArray32(value.lookup_anchor_header_hash.0),
            lookup_anchor_slot: value.lookup_anchor_timeslot,
            prerequisites: value
                .prerequisite_work_packages
                .into_iter()
                .map(|h| AsnByteArray32(h.0))
                .collect(),
        }
    }
}

// ----------------------------------------------------
// -- Authorizations
// ----------------------------------------------------

type AsnAuthorizerHash = AsnOpaqueHash;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnAuthorizer {
    pub code_hash: AsnOpaqueHash,
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

impl From<Authorizer> for AsnAuthorizer {
    fn from(value: Authorizer) -> Self {
        Self {
            code_hash: value.auth_code_hash.into(),
            params: value.param_blob.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnAuthPool(Vec<AsnAuthorizerHash>);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnAuthPools([AsnAuthPool; ASN_CORE_COUNT]);

impl From<AsnAuthPools> for AuthPool {
    fn from(value: AsnAuthPools) -> Self {
        let pool = value
            .0
            .map(|p| p.0.iter().map(|h| ByteArray::new(h.0)).collect::<Vec<_>>());
        Self(Box::new(pool))
    }
}

impl From<AuthPool> for AsnAuthPools {
    fn from(value: AuthPool) -> Self {
        let asn_pool = value.0.map(|hashes| {
            let asn_hashes = hashes
                .iter()
                .map(|h| AsnByteArray32(h.0))
                .collect::<Vec<_>>();
            AsnAuthPool(asn_hashes)
        });
        Self(asn_pool)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnAuthQueue(Vec<AsnAuthorizerHash>);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnAuthQueues([AsnAuthQueue; ASN_CORE_COUNT]);

impl From<AsnAuthQueues> for AuthQueue {
    fn from(value: AsnAuthQueues) -> Self {
        let queue = value.0.map(|q| {
            let mut hashes = [Hash32::default(); MAX_AUTH_QUEUE_SIZE];
            for (i, h) in q.0.iter().enumerate() {
                hashes[i] = ByteArray::new(h.0);
            }
            hashes
        });
        Self(Box::new(queue))
    }
}

impl From<AuthQueue> for AsnAuthQueues {
    fn from(value: AuthQueue) -> Self {
        let asn_queue = value.0.map(|q| {
            let asn_hashes = q.iter().map(|h| AsnByteArray32(h.0)).collect::<Vec<_>>();
            AsnAuthQueue(asn_hashes)
        });
        Self(asn_queue)
    }
}

// ----------------------------------------------------
// -- Work Package
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnImportSpec {
    pub tree_root: AsnOpaqueHash,
    pub index: u16,
}

impl From<AsnImportSpec> for ImportInfo {
    fn from(value: AsnImportSpec) -> Self {
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

impl From<ImportInfo> for AsnImportSpec {
    fn from(value: ImportInfo) -> Self {
        let hash = match value.work_package_id {
            WorkPackageId::SegmentRoot(h) => h,
            WorkPackageId::WorkPackageHash(h) => h,
        };

        AsnImportSpec {
            tree_root: hash.into(),
            index: value.item_index,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnExtrinsicSpec {
    pub hash: AsnOpaqueHash,
    pub len: u32,
}

impl From<AsnExtrinsicSpec> for ExtrinsicInfo {
    fn from(value: AsnExtrinsicSpec) -> Self {
        Self {
            blob_hash: ByteArray::new(value.hash.0),
            blob_length: value.len,
        }
    }
}

impl From<ExtrinsicInfo> for AsnExtrinsicSpec {
    fn from(value: ExtrinsicInfo) -> Self {
        Self {
            hash: AsnByteArray32(value.blob_hash.0),
            len: value.blob_length,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnWorkItem {
    pub service: u32,
    pub code_hash: AsnOpaqueHash,
    pub payload: AsnByteSequence,
    pub refine_gas_limit: u64,
    pub accumulate_gas_limit: u64,
    pub import_segments: Vec<AsnImportSpec>,
    pub extrinsic: Vec<AsnExtrinsicSpec>,
    pub export_count: u16,
}

impl From<AsnWorkItem> for WorkItem {
    fn from(value: AsnWorkItem) -> Self {
        Self {
            service_id: value.service,
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
            export_segment_count: value.export_count,
        }
    }
}

impl From<WorkItem> for AsnWorkItem {
    fn from(value: WorkItem) -> Self {
        Self {
            service: value.service_id,
            code_hash: value.service_code_hash.into(),
            payload: value.payload_blob.into(),
            refine_gas_limit: value.refine_gas_limit,
            accumulate_gas_limit: value.accumulate_gas_limit,
            import_segments: value
                .import_segment_ids
                .into_iter()
                .map(AsnImportSpec::from)
                .collect(),
            extrinsic: value
                .extrinsic_data_info
                .into_iter()
                .map(AsnExtrinsicSpec::from)
                .collect(),
            export_count: value.export_segment_count,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnWorkPackage {
    pub authorization: AsnByteSequence,
    pub auth_code_host: u32,
    pub authorizer: AsnAuthorizer,
    pub context: AsnRefineContext,
    pub items: Vec<AsnWorkItem>,
}

impl From<AsnWorkPackage> for WorkPackage {
    fn from(value: AsnWorkPackage) -> Self {
        Self {
            auth_token: ByteSequence::from_vec(value.authorization.0),
            authorizer_service_id: value.auth_code_host,
            authorizer: value.authorizer.into(),
            context: value.context.into(),
            work_items: value.items.into_iter().map(WorkItem::from).collect(),
        }
    }
}

impl From<WorkPackage> for AsnWorkPackage {
    fn from(value: WorkPackage) -> Self {
        Self {
            authorization: value.auth_token.into(),
            auth_code_host: value.authorizer_service_id,
            authorizer: value.authorizer.into(),
            context: value.context.into(),
            items: value
                .work_items
                .into_iter()
                .map(AsnWorkItem::from)
                .collect(),
        }
    }
}

// ----------------------------------------------------
// -- Work Report
// ----------------------------------------------------

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AsnWorkExecResult {
    ok(AsnByteSequence),
    out_of_gas,
    panic,
    bad_exports,
    bad_code,
    code_oversize,
}

impl From<AsnWorkExecResult> for WorkExecutionOutput {
    fn from(value: AsnWorkExecResult) -> Self {
        match value {
            AsnWorkExecResult::ok(bytes) => Self::Output(Octets::from_vec(bytes.0)),
            AsnWorkExecResult::out_of_gas => Self::Error(OutOfGas),
            AsnWorkExecResult::panic => Self::Error(Panic),
            AsnWorkExecResult::bad_exports => Self::Error(BadExports),
            AsnWorkExecResult::bad_code => Self::Error(Bad),
            AsnWorkExecResult::code_oversize => Self::Error(Big),
        }
    }
}

impl From<WorkExecutionOutput> for AsnWorkExecResult {
    fn from(value: WorkExecutionOutput) -> Self {
        match value {
            WorkExecutionOutput::Output(bytes) => Self::ok(AsnByteSequence(bytes.0)),
            WorkExecutionOutput::Error(OutOfGas) => Self::out_of_gas,
            WorkExecutionOutput::Error(Panic) => Self::panic,
            WorkExecutionOutput::Error(BadExports) => Self::bad_exports,
            WorkExecutionOutput::Error(Bad) => Self::bad_code,
            WorkExecutionOutput::Error(Big) => Self::code_oversize,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnWorkResult {
    pub service_id: u32,
    pub code_hash: AsnOpaqueHash,
    pub payload_hash: AsnOpaqueHash,
    pub accumulate_gas: u64,
    pub result: AsnWorkExecResult,
}

impl From<AsnWorkResult> for WorkItemResult {
    fn from(value: AsnWorkResult) -> Self {
        Self {
            service_id: value.service_id,
            service_code_hash: ByteArray::new(value.code_hash.0),
            payload_hash: ByteArray::new(value.payload_hash.0),
            gas_prioritization_ratio: value.accumulate_gas,
            refine_output: value.result.into(),
        }
    }
}

impl From<WorkItemResult> for AsnWorkResult {
    fn from(value: WorkItemResult) -> Self {
        Self {
            service_id: value.service_id,
            code_hash: AsnByteArray32(value.service_code_hash.0),
            payload_hash: AsnByteArray32(value.payload_hash.0),
            accumulate_gas: value.gas_prioritization_ratio,
            result: value.refine_output.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnWorkPackageSpec {
    pub hash: AsnOpaqueHash,
    pub length: u32,
    pub erasure_root: AsnOpaqueHash,
    pub exports_root: AsnOpaqueHash,
    pub exports_count: u16,
}

impl From<AsnWorkPackageSpec> for AvailSpecs {
    fn from(value: AsnWorkPackageSpec) -> Self {
        Self {
            work_package_hash: ByteArray::new(value.hash.0),
            work_package_length: value.length,
            erasure_root: ByteArray::new(value.erasure_root.0),
            segment_root: ByteArray::new(value.exports_root.0),
            segment_count: value.exports_count,
        }
    }
}

impl From<AvailSpecs> for AsnWorkPackageSpec {
    fn from(value: AvailSpecs) -> Self {
        Self {
            hash: AsnByteArray32(value.work_package_hash.0),
            length: value.work_package_length,
            erasure_root: AsnByteArray32(value.erasure_root.0),
            exports_root: AsnByteArray32(value.segment_root.0),
            exports_count: value.segment_count,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnSegmentRootLookupItem {
    pub work_package_hash: AsnOpaqueHash,
    pub segment_tree_root: AsnOpaqueHash,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(transparent)]
pub struct AsnSegmentRootLookupTable {
    pub items: Vec<AsnSegmentRootLookupItem>,
}

impl Deref for AsnSegmentRootLookupTable {
    type Target = Vec<AsnSegmentRootLookupItem>;

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
        let mut items: Vec<AsnSegmentRootLookupItem> = Vec::with_capacity(value.len());
        for (key, value) in value.iter() {
            items.push(AsnSegmentRootLookupItem {
                work_package_hash: AsnByteArray32(key.0),
                segment_tree_root: AsnByteArray32(value.0),
            })
        }

        AsnSegmentRootLookupTable { items }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AsnWorkReport {
    pub package_spec: AsnWorkPackageSpec,
    pub context: AsnRefineContext,
    pub core_index: u16,
    pub authorizer_hash: AsnOpaqueHash,
    pub auth_output: AsnByteSequence,
    pub segment_root_lookup: AsnSegmentRootLookupTable,
    pub results: Vec<AsnWorkResult>, // SIZE(1..4)
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
            authorizer_hash: AsnByteArray32(value.authorizer_hash.0),
            auth_output: AsnByteSequence(value.authorization_output.0),
            segment_root_lookup: value.segment_roots_lookup.into(),
            results: value.results.into_iter().map(AsnWorkResult::from).collect(),
        }
    }
}

// ----------------------------------------------------
// -- Block History
// ----------------------------------------------------

pub type AsnMmrPeak = Option<AsnOpaqueHash>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnMmr {
    peaks: Vec<AsnMmrPeak>,
}

impl<H: Hasher> From<AsnMmr> for MerkleMountainRange<H> {
    fn from(value: AsnMmr) -> Self {
        let peaks = value
            .peaks
            .into_iter()
            .map(|peak| peak.map(|hash| ByteArray::new(hash.0)))
            .collect();

        MerkleMountainRange::new_from_peaks(peaks)
    }
}

impl<H: Hasher> From<MerkleMountainRange<H>> for AsnMmr {
    fn from(value: MerkleMountainRange<H>) -> Self {
        let peaks = value
            .peaks
            .into_iter()
            .map(|peak| peak.map(|hash| AsnByteArray32(hash.0)))
            .collect();

        AsnMmr { peaks }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnReported {
    pub hash: AsnOpaqueHash,
    pub exports_root: AsnOpaqueHash,
}

pub type Reports = Vec<AsnReported>;

// Recorded disputes sequences and offenders
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnBlockInfo {
    header_hash: AsnOpaqueHash,
    mmr: AsnMmr,
    state_root: AsnOpaqueHash,
    reported: Reports,
}

impl From<AsnBlockInfo> for BlockHistoryEntry {
    fn from(value: AsnBlockInfo) -> Self {
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

impl From<BlockHistoryEntry> for AsnBlockInfo {
    fn from(value: BlockHistoryEntry) -> Self {
        Self {
            header_hash: AsnByteArray32(value.header_hash.0),
            mmr: value.accumulation_result_mmr.into(),
            state_root: AsnByteArray32(value.state_root.0),
            reported: value
                .reported_packages
                .into_iter()
                .map(|package| AsnReported {
                    hash: AsnByteArray32(package.work_package_hash.0),
                    exports_root: AsnByteArray32(package.segment_root.0),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnBlocksHistory(pub Vec<AsnBlockInfo>);

impl From<AsnBlocksHistory> for BlockHistory {
    fn from(value: AsnBlocksHistory) -> Self {
        Self(value.0.into_iter().map(BlockHistoryEntry::from).collect())
    }
}

impl From<BlockHistory> for AsnBlocksHistory {
    fn from(value: BlockHistory) -> Self {
        Self(value.0.into_iter().map(AsnBlockInfo::from).collect())
    }
}

// ----------------------------------------------------
// -- Statistics
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct AsnActivityRecord {
    pub blocks: u32,
    pub tickets: u32,
    pub pre_images: u32,
    pub pre_images_size: u32,
    pub guarantees: u32,
    pub assurances: u32,
}

impl From<ValidatorStatEntry> for AsnActivityRecord {
    fn from(value: ValidatorStatEntry) -> Self {
        Self {
            blocks: value.blocks_produced_count,
            tickets: value.tickets_count,
            pre_images: value.preimages_count,
            pre_images_size: value.preimage_data_octets_count,
            guarantees: value.guarantees_count,
            assurances: value.assurances_count,
        }
    }
}

impl From<AsnActivityRecord> for ValidatorStatEntry {
    fn from(value: AsnActivityRecord) -> Self {
        Self {
            blocks_produced_count: value.blocks,
            tickets_count: value.tickets,
            preimages_count: value.pre_images,
            preimage_data_octets_count: value.pre_images_size,
            guarantees_count: value.guarantees,
            assurances_count: value.assurances,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnActivityRecords([AsnActivityRecord; ASN_VALIDATORS_COUNT]);

impl From<EpochValidatorStats> for AsnActivityRecords {
    fn from(value: EpochValidatorStats) -> Self {
        let mut records = from_fn(|_| AsnActivityRecord::default());
        for (i, entry) in value.iter().enumerate() {
            records[i] = AsnActivityRecord::from(*entry);
        }
        Self(records)
    }
}

impl From<AsnActivityRecords> for EpochValidatorStats {
    fn from(value: AsnActivityRecords) -> Self {
        let mut stats = from_fn(|_| ValidatorStatEntry::default());
        for (i, record) in value.0.into_iter().enumerate() {
            stats[i] = ValidatorStatEntry::from(record);
        }
        Self::new(Box::new(stats))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnStatistics {
    current: AsnActivityRecords,
    last: AsnActivityRecords,
}

impl From<ValidatorStats> for AsnStatistics {
    fn from(value: ValidatorStats) -> Self {
        Self {
            current: AsnActivityRecords::from(value.0[0].clone()),
            last: AsnActivityRecords::from(value.0[1].clone()),
        }
    }
}

impl From<AsnStatistics> for ValidatorStats {
    fn from(value: AsnStatistics) -> Self {
        let mut array = from_fn(|_| EpochValidatorStats::default());
        array[0] = EpochValidatorStats::from(value.current);
        array[1] = EpochValidatorStats::from(value.last);

        Self(array)
    }
}

// ----------------------------------------------------
// -- Tickets
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default, Copy, PartialEq)]
pub struct AsnTicketBody {
    pub attempt: u8,
    pub id: AsnOpaqueHash,
}

impl From<AsnTicketBody> for Ticket {
    fn from(value: AsnTicketBody) -> Self {
        Self {
            attempt: value.attempt,
            id: ByteArray::new(value.id.0),
        }
    }
}

impl From<Ticket> for AsnTicketBody {
    fn from(ticket: Ticket) -> Self {
        AsnTicketBody {
            id: AsnByteArray32(ticket.id.0),
            attempt: ticket.attempt,
        }
    }
}

pub type AsnTicketsBodies = [AsnTicketBody; ASN_EPOCH_LENGTH];
pub type AsnEpochKeys = [AsnBandersnatchKey; ASN_EPOCH_LENGTH];

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum AsnTicketsOrKeys {
    tickets(AsnTicketsBodies),
    keys(AsnEpochKeys),
}

impl From<AsnTicketsOrKeys> for SlotSealerType {
    fn from(value: AsnTicketsOrKeys) -> Self {
        match value {
            AsnTicketsOrKeys::tickets(ticket_bodies) => {
                let mut tickets: [Ticket; ASN_EPOCH_LENGTH] = Default::default();
                for (i, ticket_body) in ticket_bodies.into_iter().enumerate() {
                    tickets[i] = Ticket {
                        id: ByteArray::new(ticket_body.id.0),
                        attempt: ticket_body.attempt,
                    };
                }
                SlotSealerType::Tickets(Box::new(tickets))
            }
            AsnTicketsOrKeys::keys(epoch_keys) => {
                let mut keys: [BandersnatchPubKey; ASN_EPOCH_LENGTH] = Default::default();
                for (i, key) in epoch_keys.into_iter().enumerate() {
                    keys[i] = ByteArray::new(key.0)
                }
                SlotSealerType::BandersnatchPubKeys(Box::new(keys))
            }
        }
    }
}

impl From<SlotSealerType> for AsnTicketsOrKeys {
    fn from(value: SlotSealerType) -> Self {
        match value {
            SlotSealerType::Tickets(tickets) => {
                let mut ticket_bodies: AsnTicketsBodies = Default::default();
                for (i, ticket) in tickets.into_iter().enumerate() {
                    ticket_bodies[i] = AsnTicketBody {
                        id: AsnByteArray32(ticket.id.0),
                        attempt: ticket.attempt,
                    };
                }
                AsnTicketsOrKeys::tickets(ticket_bodies)
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                let mut epoch_keys: AsnEpochKeys = Default::default();
                for (i, key) in keys.into_iter().enumerate() {
                    epoch_keys[i] = AsnByteArray32(key.0);
                }
                AsnTicketsOrKeys::keys(epoch_keys)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnTicketEnvelope {
    pub attempt: u8,
    pub signature: AsnBandersnatchRingSignature,
}

impl From<AsnTicketEnvelope> for TicketsXtEntry {
    fn from(value: AsnTicketEnvelope) -> Self {
        Self {
            ticket_proof: Box::new(ByteArray::new(value.signature.0)),
            entry_index: value.attempt,
        }
    }
}

impl From<TicketsXtEntry> for AsnTicketEnvelope {
    fn from(value: TicketsXtEntry) -> Self {
        Self {
            signature: AsnBandersnatchRingSignature(value.ticket_proof.0),
            attempt: value.entry_index,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnTicketsXt(pub Vec<AsnTicketEnvelope>);

impl From<AsnTicketsXt> for TicketsXt {
    fn from(value: AsnTicketsXt) -> Self {
        Self {
            items: value.0.into_iter().map(TicketsXtEntry::from).collect(),
        }
    }
}

impl From<TicketsXt> for AsnTicketsXt {
    fn from(value: TicketsXt) -> Self {
        Self(
            value
                .items
                .into_iter()
                .map(AsnTicketEnvelope::from)
                .collect(),
        )
    }
}

// ----------------------------------------------------
// -- Disputes
// ----------------------------------------------------

pub type AsnEpochIndex = u32;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AsnDisputeJudgement {
    pub vote: bool,
    pub index: u16,
    pub signature: AsnEd25519Signature,
}

impl From<AsnDisputeJudgement> for Judgment {
    fn from(value: AsnDisputeJudgement) -> Self {
        Self {
            is_report_valid: value.vote,
            voter: value.index,
            voter_signature: value.signature.into(),
        }
    }
}

impl From<Judgment> for AsnDisputeJudgement {
    fn from(value: Judgment) -> Self {
        Self {
            vote: value.is_report_valid,
            index: value.voter,
            signature: value.voter_signature.into(),
        }
    }
}

pub type DisputeJudgements = [AsnDisputeJudgement; ASN_VALIDATORS_SUPER_MAJORITY];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnDisputeVerdict {
    pub target: AsnWorkReportHash,
    pub age: AsnEpochIndex,
    pub votes: DisputeJudgements,
}

impl From<AsnDisputeVerdict> for Verdict {
    fn from(value: AsnDisputeVerdict) -> Self {
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

impl From<Verdict> for AsnDisputeVerdict {
    fn from(value: Verdict) -> Self {
        let mut votes: [AsnDisputeJudgement; ASN_VALIDATORS_SUPER_MAJORITY] = Default::default();
        for (i, judgment) in value.judgments.iter().enumerate() {
            votes[i] = AsnDisputeJudgement {
                vote: judgment.is_report_valid,
                index: judgment.voter,
                signature: AsnByteArray64(judgment.voter_signature.0),
            };
        }

        AsnDisputeVerdict {
            target: AsnByteArray32(value.report_hash.0),
            age: value.epoch_index,
            votes,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnDisputeCulpritProof {
    pub target: AsnWorkReportHash,
    pub key: AsnEd25519Key,
    pub signature: AsnEd25519Signature,
}

impl From<AsnDisputeCulpritProof> for Culprit {
    fn from(value: AsnDisputeCulpritProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<Culprit> for AsnDisputeCulpritProof {
    fn from(value: Culprit) -> Self {
        Self {
            target: AsnByteArray32(value.report_hash.0),
            key: AsnByteArray32(value.validator_key.0),
            signature: AsnByteArray64(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnDisputeFaultProof {
    pub target: AsnWorkReportHash,
    pub vote: bool,
    pub key: AsnEd25519Key,
    pub signature: AsnEd25519Signature,
}

impl From<AsnDisputeFaultProof> for Fault {
    fn from(value: AsnDisputeFaultProof) -> Self {
        Self {
            report_hash: ByteArray::new(value.target.0),
            is_report_valid: value.vote,
            validator_key: ByteArray::new(value.key.0),
            signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<Fault> for AsnDisputeFaultProof {
    fn from(value: Fault) -> Self {
        Self {
            target: AsnByteArray32(value.report_hash.0),
            vote: value.is_report_valid,
            key: AsnByteArray32(value.validator_key.0),
            signature: AsnByteArray64(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnDisputesOutputMarks {
    pub offenders_mark: Vec<AsnEd25519Key>,
}

impl From<OffendersHeaderMarker> for AsnDisputesOutputMarks {
    fn from(value: OffendersHeaderMarker) -> Self {
        let offenders_mark = value.items.into_iter().map(AsnByteArray32::from).collect();
        Self { offenders_mark }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnDisputesRecords {
    pub good: Vec<AsnWorkReportHash>,  // Good verdicts
    pub bad: Vec<AsnWorkReportHash>,   // Bad verdicts
    pub wonky: Vec<AsnWorkReportHash>, // Wonky verdicts
    pub offenders: Vec<AsnEd25519Key>, // Offenders
}

impl From<AsnDisputesRecords> for DisputesState {
    fn from(value: AsnDisputesRecords) -> Self {
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

impl From<DisputesState> for AsnDisputesRecords {
    fn from(value: DisputesState) -> Self {
        Self {
            good: value
                .good_set
                .into_iter()
                .map(AsnByteArray32::from)
                .collect(),
            bad: value
                .bad_set
                .into_iter()
                .map(AsnByteArray32::from)
                .collect(),
            wonky: value
                .wonky_set
                .into_iter()
                .map(AsnByteArray32::from)
                .collect(),
            offenders: value
                .punish_set
                .into_iter()
                .map(AsnByteArray32::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnDisputesXt {
    pub verdicts: Vec<AsnDisputeVerdict>,
    pub culprits: Vec<AsnDisputeCulpritProof>,
    pub faults: Vec<AsnDisputeFaultProof>,
}

impl From<AsnDisputesXt> for DisputesXt {
    fn from(value: AsnDisputesXt) -> Self {
        Self {
            verdicts: value.verdicts.into_iter().map(Verdict::from).collect(),
            culprits: value.culprits.into_iter().map(Culprit::from).collect(),
            faults: value.faults.into_iter().map(Fault::from).collect(),
        }
    }
}

impl From<DisputesXt> for AsnDisputesXt {
    fn from(value: DisputesXt) -> Self {
        Self {
            verdicts: value
                .verdicts
                .into_iter()
                .map(AsnDisputeVerdict::from)
                .collect(),
            culprits: value
                .culprits
                .into_iter()
                .map(AsnDisputeCulpritProof::from)
                .collect(),
            faults: value
                .faults
                .into_iter()
                .map(AsnDisputeFaultProof::from)
                .collect(),
        }
    }
}

// ----------------------------------------------------
// -- Preimages
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnPreimage {
    pub requester: u32,
    pub blob: AsnByteSequence,
}

impl From<AsnPreimage> for PreimagesXtEntry {
    fn from(value: AsnPreimage) -> Self {
        Self {
            service_id: value.requester,
            preimage_data: ByteSequence::from_vec(value.blob.0),
        }
    }
}

impl From<PreimagesXtEntry> for AsnPreimage {
    fn from(value: PreimagesXtEntry) -> Self {
        Self {
            requester: value.service_id,
            blob: AsnByteSequence(value.preimage_data.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnPreimagesXt(pub Vec<AsnPreimage>);

impl From<AsnPreimagesXt> for PreimagesXt {
    fn from(value: AsnPreimagesXt) -> Self {
        Self {
            items: value.0.into_iter().map(PreimagesXtEntry::from).collect(),
        }
    }
}

impl From<PreimagesXt> for AsnPreimagesXt {
    fn from(value: PreimagesXt) -> Self {
        Self(value.items.into_iter().map(AsnPreimage::from).collect())
    }
}

// ----------------------------------------------------
// -- Assurances
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnAvailAssurance {
    pub anchor: AsnOpaqueHash,
    pub bitfield: AsnByteSequence, // SIZE(AVAIL_BITFIELD_BYTES)
    pub validator_index: u16,
    pub signature: AsnEd25519Signature,
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

impl From<AsnAvailAssurance> for AssurancesXtEntry {
    fn from(value: AsnAvailAssurance) -> Self {
        Self {
            anchor_parent_hash: ByteArray::new(value.anchor.0),
            assuring_cores_bitvec: bytes_to_bitvec(&value.bitfield.0, ASN_CORE_COUNT),
            validator_index: value.validator_index,
            signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<AssurancesXtEntry> for AsnAvailAssurance {
    fn from(value: AssurancesXtEntry) -> Self {
        let mut rev = BitVec::new();
        for b in value.assuring_cores_bitvec.iter().rev() {
            rev.push(b);
        }

        let mut bytes = rev.to_bytes();
        let bytes_count = ASN_CORE_COUNT.div_ceil(8);
        bytes.resize(bytes_count, 0u8);

        Self {
            anchor: value.anchor_parent_hash.into(),
            bitfield: bytes.into(),
            validator_index: value.validator_index,
            signature: value.signature.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnAssurancesXt(pub Vec<AsnAvailAssurance>);

impl From<AsnAssurancesXt> for AssurancesXt {
    fn from(value: AsnAssurancesXt) -> Self {
        Self {
            items: value.0.into_iter().map(AssurancesXtEntry::from).collect(),
        }
    }
}

impl From<AssurancesXt> for AsnAssurancesXt {
    fn from(value: AssurancesXt) -> Self {
        Self(
            value
                .items
                .into_iter()
                .map(AsnAvailAssurance::from)
                .collect(),
        )
    }
}

// ----------------------------------------------------
// -- Guarantees
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnValidatorSignature {
    pub validator_index: u16,
    pub signature: AsnEd25519Signature,
}

impl From<AsnValidatorSignature> for GuaranteesCredential {
    fn from(value: AsnValidatorSignature) -> Self {
        Self {
            validator_index: value.validator_index,
            signature: ByteArray::new(value.signature.0),
        }
    }
}

impl From<GuaranteesCredential> for AsnValidatorSignature {
    fn from(value: GuaranteesCredential) -> Self {
        Self {
            validator_index: value.validator_index,
            signature: AsnByteArray64(value.signature.0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnReportGuarantee {
    pub report: AsnWorkReport,
    pub slot: u32,
    pub signatures: Vec<AsnValidatorSignature>,
}

impl From<AsnReportGuarantee> for GuaranteesXtEntry {
    fn from(value: AsnReportGuarantee) -> Self {
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

impl From<GuaranteesXtEntry> for AsnReportGuarantee {
    fn from(value: GuaranteesXtEntry) -> Self {
        Self {
            report: value.work_report.into(),
            slot: value.timeslot_index,
            signatures: value
                .credentials
                .into_iter()
                .map(AsnValidatorSignature::from)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnGuaranteesXt(pub Vec<AsnReportGuarantee>);

impl From<AsnGuaranteesXt> for GuaranteesXt {
    fn from(value: AsnGuaranteesXt) -> Self {
        Self {
            items: value.0.into_iter().map(GuaranteesXtEntry::from).collect(),
        }
    }
}

impl From<GuaranteesXt> for AsnGuaranteesXt {
    fn from(value: GuaranteesXt) -> Self {
        Self(
            value
                .items
                .into_iter()
                .map(AsnReportGuarantee::from)
                .collect(),
        )
    }
}

// ----------------------------------------------------
// -- Header
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AsnEpochMark {
    pub entropy: AsnOpaqueHash,
    pub tickets_entropy: AsnOpaqueHash,
    pub validators: Vec<AsnBandersnatchKey>, // SIZE(validators-count)
}

impl From<AsnEpochMark> for EpochMarker {
    fn from(value: AsnEpochMark) -> Self {
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

impl From<EpochMarker> for AsnEpochMark {
    fn from(marker: EpochMarker) -> Self {
        AsnEpochMark {
            entropy: AsnByteArray32(marker.entropy.0),
            tickets_entropy: AsnByteArray32(marker.tickets_entropy.0),
            validators: marker
                .validators
                .into_iter()
                .map(AsnByteArray32::from)
                .collect(),
        }
    }
}

pub type AsnTicketsMark = [AsnTicketBody; ASN_EPOCH_LENGTH];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnHeader {
    pub parent: AsnOpaqueHash,
    pub parent_state_root: AsnOpaqueHash,
    pub extrinsic_hash: AsnOpaqueHash,
    pub slot: u32,
    pub epoch_mark: Option<AsnEpochMark>,
    pub tickets_mark: Option<Vec<AsnTicketBody>>,
    pub offenders_mark: Vec<AsnEd25519Key>,
    pub author_index: u16,
    pub entropy_source: AsnBandersnatchVrfSignature,
    pub seal: AsnBandersnatchVrfSignature,
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
                let mut tickets_array = [Ticket::default(); ASN_EPOCH_LENGTH];
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

impl From<BlockHeader> for AsnHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            parent: AsnByteArray32(value.parent_hash.0),
            parent_state_root: AsnByteArray32(value.parent_state_root.0),
            extrinsic_hash: AsnByteArray32(value.extrinsic_hash.0),
            slot: value.timeslot_index,
            epoch_mark: value.epoch_marker.map(AsnEpochMark::from),
            tickets_mark: value.winning_tickets_marker.map(|tickets_arr| {
                tickets_arr
                    .iter()
                    .map(|ticket| AsnTicketBody {
                        attempt: ticket.attempt,
                        id: AsnByteArray32(ticket.id.0),
                    })
                    .collect::<Vec<_>>()
            }),
            offenders_mark: value
                .offenders_marker
                .into_iter()
                .map(|offender_key| AsnByteArray32(offender_key.0))
                .collect(),
            author_index: value.block_author_index,
            entropy_source: AsnBandersnatchVrfSignature(value.vrf_signature.0),
            seal: AsnBandersnatchVrfSignature(value.block_seal.0),
        }
    }
}

// ----------------------------------------------------
// -- Header
// ----------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsnExtrinsic {
    pub tickets: AsnTicketsXt,
    pub disputes: AsnDisputesXt,
    pub preimages: AsnPreimagesXt,
    pub assurances: AsnAssurancesXt,
    pub guarantees: AsnGuaranteesXt,
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

impl From<Extrinsics> for AsnExtrinsic {
    fn from(value: Extrinsics) -> Self {
        Self {
            tickets: value.tickets.into(),
            disputes: value.disputes.into(),
            preimages: value.preimage_lookups.into(),
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

impl From<Block> for AsnBlock {
    fn from(value: Block) -> Self {
        Self {
            header: value.header.into(),
            extrinsic: value.extrinsics.into(),
        }
    }
}
