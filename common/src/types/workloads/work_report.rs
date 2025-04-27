use crate::{
    workloads::common::RefinementContext, CoreIndex, Hash32, Octets, ServiceId, UnsignedGas,
};
use rjam_codec::prelude::*;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
    ops::Deref,
};
use thiserror::Error;

// FIXME: remove
#[derive(Debug, Error)]
pub enum WorkReportError {
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

/// Represents a work report generated from refinement of a work package,
/// to be integrated into the on-chain state via the accumulation process.
///
/// In Report (Guarantees) extrinsics, work reports must be ordered by core index in ascending order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkReport {
    /// `s`: Work package availability specification
    pub specs: AvailSpecs,
    /// `x`: Refinement context
    pub refinement_context: RefinementContext,
    /// `c`: Core index on which the work is done
    pub core_index: CoreIndex,
    /// `a`: Authorizer hash
    pub authorizer_hash: Hash32,
    /// **`o`**: Authorization trace
    pub auth_trace: Octets,
    /// **`l`**: Segment-root lookup dictionary, up to 8 items
    pub segment_roots_lookup: SegmentRootLookupTable,
    /// **`r`**: Work digests, with at least 1 and no more than 16 items
    pub digests: Vec<WorkDigest>,
    /// `g`: The amount of gas used in `is_authorized` invocation, prior to the refinement.
    pub auth_gas_used: UnsignedGas,
}

impl Display for WorkReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "WorkReport {{")?;
        writeln!(f, "\tspec: {}", self.specs)?;
        writeln!(f, "\trefine_ctx: {}", self.refinement_context)?;
        writeln!(f, "\tcore_idx: {}", self.core_index)?;
        writeln!(f, "\tauth_hash: {}", self.authorizer_hash)?;
        writeln!(f, "\tauth_trace: {}", self.auth_trace)?;
        writeln!(f, "\tsegment_roots_lookup: {}", self.segment_roots_lookup)?;
        if self.digests.is_empty() {
            writeln!(f, "\tdigests: []")?;
        } else {
            writeln!(f, "\tdigests: [")?;
            for digest in self.digests.iter() {
                writeln!(f, "\t  {digest}")?;
            }
            writeln!(f, "\t]")?;
        }
        write!(f, "  }}")
    }
}

impl JamEncode for WorkReport {
    fn size_hint(&self) -> usize {
        self.specs.size_hint()
            + self.refinement_context.size_hint()
            + 2
            + self.authorizer_hash.size_hint()
            + self.auth_trace.size_hint()
            + self.segment_roots_lookup.size_hint()
            + self.digests.size_hint()
            + self.auth_gas_used.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.specs.encode_to(dest)?;
        self.refinement_context.encode_to(dest)?;
        self.core_index.encode_to_fixed(dest, 2)?; // TODO: check - Not fixed encoding in GP
        self.authorizer_hash.encode_to(dest)?;
        self.auth_trace.encode_to(dest)?;
        self.segment_roots_lookup.encode_to(dest)?;
        self.digests.encode_to(dest)?;
        self.auth_gas_used.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkReport {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            specs: AvailSpecs::decode(input)?,
            refinement_context: RefinementContext::decode(input)?,
            core_index: CoreIndex::decode_fixed(input, 2)?,
            authorizer_hash: Hash32::decode(input)?,
            auth_trace: Octets::decode(input)?,
            segment_roots_lookup: SegmentRootLookupTable::decode(input)?,
            digests: Vec::<WorkDigest>::decode(input)?,
            auth_gas_used: UnsignedGas::decode(input)?,
        })
    }
}

impl PartialOrd for WorkReport {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.core_index.cmp(&other.core_index))
    }
}

impl Ord for WorkReport {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core_index.cmp(&other.core_index)
    }
}

impl WorkReport {
    pub fn refinement_context(&self) -> &RefinementContext {
        &self.refinement_context
    }

    pub fn prerequisites(&self) -> &BTreeSet<Hash32> {
        &self.refinement_context.prerequisite_work_packages
    }

    pub fn segment_roots_lookup(&self) -> &BTreeMap<Hash32, Hash32> {
        &self.segment_roots_lookup
    }

    pub fn work_package_hash(&self) -> &Hash32 {
        &self.specs.work_package_hash
    }

    pub fn segment_root(&self) -> &Hash32 {
        &self.specs.segment_root
    }

    pub fn digests(&self) -> &[WorkDigest] {
        &self.digests
    }

    pub fn auth_trace(&self) -> &[u8] {
        &self.auth_trace
    }

    pub fn core_index(&self) -> CoreIndex {
        self.core_index
    }

    pub fn authorizer_hash(&self) -> &Hash32 {
        &self.authorizer_hash
    }

    pub fn total_output_size(&self) -> usize {
        self.auth_trace.len()
            + self
                .digests
                .iter()
                .map(|wd| wd.output_bytes())
                .sum::<usize>()
    }

    pub fn total_accumulation_gas_allotted(&self) -> UnsignedGas {
        self.digests.iter().map(|wd| wd.accumulate_gas_limit).sum()
    }

    pub fn extract_exports_manifest(&self) -> ReportedWorkPackage {
        ReportedWorkPackage {
            work_package_hash: self.specs.work_package_hash.clone(),
            segment_root: self.specs.segment_root.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct SegmentRootLookupTable {
    items: BTreeMap<Hash32, Hash32>,
}

impl Display for SegmentRootLookupTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            write!(f, "SegmentRootLookupTable: {{}}")?;
        } else {
            writeln!(f, "SegmentRootLookupTable: {{")?;
            for (k, v) in self.items.iter() {
                writeln!(f, "  {}: {}", &k, &v)?;
            }
            writeln!(f, "}}")?;
        }
        Ok(())
    }
}

impl Deref for SegmentRootLookupTable {
    type Target = BTreeMap<Hash32, Hash32>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl SegmentRootLookupTable {
    pub fn new(items: BTreeMap<Hash32, Hash32>) -> Self {
        Self { items }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailSpecs {
    /// `h`: Work package hash
    pub work_package_hash: Hash32,
    /// `l`: Auditable work bundle length
    pub work_bundle_length: u32,
    /// `u`: Erasure root of the work package
    pub erasure_root: Hash32,
    /// `e`: Export segment root of the work package
    pub segment_root: Hash32,
    /// `n`: Number of export segments
    pub segment_count: u16,
}

impl Display for AvailSpecs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AvailSpecs {{ wp_hash: {}, wp_bundle_len: {}, erasure_root: {}, \
             segment_root: {}, segment_count: {} }}",
            self.work_package_hash,
            self.work_bundle_length,
            self.erasure_root,
            self.segment_root,
            self.segment_count,
        )
    }
}

impl JamEncode for AvailSpecs {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + 4
            + self.erasure_root.size_hint()
            + self.segment_root.size_hint()
            + 2
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.work_package_hash.encode_to(dest)?;
        self.work_bundle_length.encode_to_fixed(dest, 4)?;
        self.erasure_root.encode_to(dest)?;
        self.segment_root.encode_to(dest)?;
        self.segment_count.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for AvailSpecs {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            work_package_hash: Hash32::decode(input)?,
            work_bundle_length: u32::decode_fixed(input, 4)?,
            erasure_root: Hash32::decode(input)?,
            segment_root: Hash32::decode(input)?,
            segment_count: u16::decode_fixed(input, 2)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, JamEncode, JamDecode)]
pub struct ReportedWorkPackage {
    /// `h` of `AvailSpec` from work report in `GuaranteesXt`
    pub work_package_hash: Hash32,
    /// `e` of `AvailSpec` from work report in `GuaranteesXt`
    pub segment_root: Hash32,
}

impl Display for ReportedWorkPackage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "package_hash: {}", self.work_package_hash)?;
        write!(f, "segment_root: {}", self.segment_root)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct RefineStats {
    /// `u`: The actual amount of gas used during refinement.
    pub refine_gas_used: UnsignedGas,
    /// `i`: The number of imported segments by the work item.
    pub imports_count: u16,
    /// `x`: The number of extrinsics items used by the work item.
    pub extrinsics_count: u16,
    /// `z`: The total size of extrinsics used by the work item, in octets.
    pub extrinsics_octets: u32,
    /// `e`: The number of exported segments by the work item.
    pub exports_count: u16,
}

impl Display for RefineStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "refine_gas_used: {}", self.refine_gas_used)?;
        writeln!(f, "imports_count: {}", self.imports_count)?;
        writeln!(f, "extrinsics_count: {}", self.extrinsics_count)?;
        writeln!(f, "extrinsics_octets: {}", self.extrinsics_octets)?;
        write!(f, "exports_count: {}", self.exports_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkDigest {
    /// `s`: Associated service id.
    pub service_id: ServiceId,
    /// `c`: Code hash of the service, at the time of reporting.
    pub service_code_hash: Hash32,
    /// `y`: Hash of the associated work item payload.
    pub payload_hash: Hash32,
    /// `g`: A gas limit allocated to the work item's accumulation.
    pub accumulate_gas_limit: UnsignedGas,
    /// **`d`**: Output or error of the execution of the work item.
    pub refine_result: WorkExecutionResult,
    /// Statistics on gas usage and data referenced in the refinement process.
    pub refine_stats: RefineStats,
}

impl Display for WorkDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "WorkDigest: {{")?;
        writeln!(f, "service_idx: {}", self.service_id)?;
        writeln!(f, "service_code_hash: {}", self.service_code_hash)?;
        writeln!(f, "payload_hash: {}", self.payload_hash)?;
        writeln!(f, "accumulate_gas_limit: {}", self.accumulate_gas_limit)?;
        writeln!(f, "refine_result: {}", self.refine_result)?;
        writeln!(f, "refine_stats: {}", self.refine_stats)?;
        write!(f, "}}")
    }
}

impl JamEncode for WorkDigest {
    fn size_hint(&self) -> usize {
        4 + self.service_code_hash.size_hint()
            + self.payload_hash.size_hint()
            + 8
            + self.refine_result.size_hint()
            + self.refine_stats.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_id.encode_to_fixed(dest, 4)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_hash.encode_to(dest)?;
        self.accumulate_gas_limit.encode_to_fixed(dest, 8)?;
        self.refine_result.encode_to(dest)?;
        self.refine_stats.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkDigest {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service_id: ServiceId::decode_fixed(input, 4)?,
            service_code_hash: Hash32::decode(input)?,
            payload_hash: Hash32::decode(input)?,
            accumulate_gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            refine_result: WorkExecutionResult::decode(input)?,
            refine_stats: RefineStats::decode(input)?,
        })
    }
}

impl WorkDigest {
    fn output_bytes(&self) -> usize {
        match &self.refine_result {
            WorkExecutionResult::Output(bytes) => bytes.len(),
            WorkExecutionResult::Error(_) => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionResult {
    Output(Octets),
    Error(WorkExecutionError),
}

impl Display for WorkExecutionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Output(octets) => {
                write!(f, "{octets}")
            }
            Self::Error(err) => {
                write!(f, "{err:?}")
            }
        }
    }
}

impl JamEncode for WorkExecutionResult {
    fn size_hint(&self) -> usize {
        match self {
            WorkExecutionResult::Output(data) => {
                1 + data.size_hint() // with 1 byte prefix
            }
            WorkExecutionResult::Error(_) => 1, // 1 byte succinct encoding
        }
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        match self {
            WorkExecutionResult::Output(data) => {
                0u8.encode_to(dest)?; // prefix (0) for Output
                data.encode_to(dest)?;
                Ok(())
            }
            WorkExecutionResult::Error(error) => match error {
                WorkExecutionError::OutOfGas => 1u8.encode_to(dest),
                WorkExecutionError::Panic => 2u8.encode_to(dest),
                WorkExecutionError::BadExports => 3u8.encode_to(dest),
                WorkExecutionError::Bad => 4u8.encode_to(dest),
                WorkExecutionError::Big => 5u8.encode_to(dest),
            },
        }
    }
}

impl JamDecode for WorkExecutionResult {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            0 => {
                let data = Octets::decode(input)?;
                Ok(WorkExecutionResult::Output(data))
            }
            1 => Ok(WorkExecutionResult::Error(WorkExecutionError::OutOfGas)),
            2 => Ok(WorkExecutionResult::Error(WorkExecutionError::Panic)),
            3 => Ok(WorkExecutionResult::Error(WorkExecutionError::BadExports)),
            4 => Ok(WorkExecutionResult::Error(WorkExecutionError::Bad)),
            5 => Ok(WorkExecutionResult::Error(WorkExecutionError::Big)),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionResult prefix".into(),
            )),
        }
    }
}

impl WorkExecutionResult {
    pub fn ok(output: Vec<u8>) -> Self {
        Self::Output(Octets::from_vec(output))
    }

    pub fn ok_empty() -> Self {
        Self::Output(Octets::default())
    }

    pub fn out_of_gas() -> Self {
        Self::Error(WorkExecutionError::OutOfGas)
    }

    pub fn panic() -> Self {
        Self::Error(WorkExecutionError::Panic)
    }

    pub fn wrong_exports_count() -> Self {
        Self::Error(WorkExecutionError::BadExports)
    }

    pub fn bad() -> Self {
        Self::Error(WorkExecutionError::Bad)
    }

    pub fn big() -> Self {
        Self::Error(WorkExecutionError::Big)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionError {
    /// `∞`: Out of gas
    OutOfGas,
    /// `☇`: Panic on execution
    Panic,
    /// `⊚`: The reported number of exports made is invalid
    BadExports,
    /// `BAD`: Service code not available for lookup
    Bad,
    /// `BIG`: Code size exceeds `MAX_SERVICE_CODE_SIZE`
    Big,
}

impl JamDecode for WorkExecutionError {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            1 => Ok(WorkExecutionError::OutOfGas),
            2 => Ok(WorkExecutionError::Panic),
            3 => Ok(WorkExecutionError::BadExports),
            4 => Ok(WorkExecutionError::Bad),
            5 => Ok(WorkExecutionError::Big),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionError prefix".into(),
            )),
        }
    }
}
