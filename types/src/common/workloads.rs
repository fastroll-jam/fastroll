use crate::state::ReportedWorkPackage;
use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{Address, CoreIndex, Hash32, Octets, UnsignedGas, HASH_SIZE};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    fmt::{Display, Formatter},
    ops::Deref,
};
use thiserror::Error;

// TODO: remove
#[derive(Debug, Error)]
pub enum WorkReportError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkPackageId {
    /// `h`: Export segments root
    SegmentRoot(Hash32),
    /// `h+` (boxplus): Exporting work-package hash
    WorkPackageHash(Hash32),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct Authorizer {
    /// `u`: Authorization code hash
    pub auth_code_hash: Hash32,
    /// **`p`**: Authorization param blob
    pub param_blob: Octets,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkPackage {
    /// **`j`**: Authorizer token blob
    pub auth_token: Octets,
    /// `h`: Authorization code host service address
    pub authorizer_address: Address,
    /// `u` & **`p`**: Authorization code hash and param blob
    pub authorizer: Authorizer,
    /// **`x`**: Refinement context
    pub context: RefinementContext,
    /// **`w`**: Sequence of work items (4 items at most)
    pub work_items: Vec<WorkItem>,
}

impl JamEncode for WorkPackage {
    fn size_hint(&self) -> usize {
        self.auth_token.size_hint()
            + 4
            + self.authorizer.size_hint()
            + self.context.size_hint()
            + self.work_items.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.auth_token.encode_to(dest)?;
        self.authorizer_address.encode_to_fixed(dest, 4)?;
        self.authorizer.encode_to(dest)?;
        self.context.encode_to(dest)?;
        self.work_items.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkPackage {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            auth_token: Octets::decode(input)?,
            authorizer_address: Address::decode_fixed(input, 4)?,
            authorizer: Authorizer::decode(input)?,
            context: RefinementContext::decode(input)?,
            work_items: Vec::<WorkItem>::decode(input)?,
        })
    }
}

impl WorkPackage {
    pub fn hash(&self) -> Result<Hash32, CryptoError> {
        hash::<Blake2b256>(
            self.encode()
                .map_err(|_| CryptoError::HashError)?
                .as_slice(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    /// `h` or `h+`: Work package id
    pub work_package_id: WorkPackageId,
    /// `i`: Work item index within the work package, up to 2^15
    pub item_index: u16,
}

impl JamEncode for ImportInfo {
    fn size_hint(&self) -> usize {
        HASH_SIZE + 2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        let (hash, item_index) = match self.work_package_id {
            WorkPackageId::SegmentRoot(hash) => (hash, self.item_index),
            WorkPackageId::WorkPackageHash(hash) => (hash, self.item_index + (1 << 15)),
        };
        hash.encode_to(dest)?;
        item_index.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for ImportInfo {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let hash = Hash32::decode(input)?;
        let item_index = u16::decode_fixed(input, 2)?;

        let work_package_id = if item_index >= (1 << 15) {
            WorkPackageId::WorkPackageHash(hash) // the `boxplus` tagged variant of hash
        } else {
            WorkPackageId::SegmentRoot(hash)
        };

        let original_item_index = if let WorkPackageId::WorkPackageHash(_) = work_package_id {
            item_index - (1 << 15)
        } else {
            item_index
        };

        Ok(ImportInfo {
            work_package_id,
            item_index: original_item_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtrinsicInfo {
    /// `h`: Extrinsic data hash
    pub blob_hash: Hash32,
    /// `i`: Extrinsic data size
    pub blob_length: u32,
}

impl JamEncode for ExtrinsicInfo {
    fn size_hint(&self) -> usize {
        self.blob_hash.size_hint() + 4
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.blob_hash.encode_to(dest)?;
        self.blob_length.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for ExtrinsicInfo {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            blob_hash: Hash32::decode(input)?,
            blob_length: u32::decode_fixed(input, 4)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    /// `s`: Associated service index
    pub service_index: Address,
    /// `c`: Code hash of the service, at the time of reporting
    pub service_code_hash: Hash32,
    /// **`y`**: Work item payload blob
    pub payload_blob: Octets,
    /// `g`: Service-specific gas limit for Refinement
    pub refine_gas_limit: UnsignedGas,
    /// `a`: Service-specific gas limit for Accumulation
    pub accumulate_gas_limit: UnsignedGas,
    /// **`i`**: Import segments info (hash and index).
    /// max length = `IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT`
    pub import_segment_ids: Vec<ImportInfo>,
    /// **`x`**: Extrinsic data info (hash and length)
    pub extrinsic_data_info: Vec<ExtrinsicInfo>,
    /// `e`: Number of export data segments exported by the work item.
    /// max value = `IMPORT_EXPORT_SEGMENTS_LENGTH_LIMIT`
    pub export_segment_count: u16,
}

impl JamEncode for WorkItem {
    fn size_hint(&self) -> usize {
        4 + self.service_code_hash.size_hint()
            + self.payload_blob.size_hint()
            + 8
            + 8
            + self.import_segment_ids.size_hint()
            + self.extrinsic_data_info.size_hint()
            + 2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_index.encode_to_fixed(dest, 4)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_blob.encode_to(dest)?;
        self.refine_gas_limit.encode_to_fixed(dest, 8)?;
        self.accumulate_gas_limit.encode_to_fixed(dest, 8)?;
        self.import_segment_ids.encode_to(dest)?;
        self.extrinsic_data_info.encode_to(dest)?;
        self.export_segment_count.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for WorkItem {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service_index: Address::decode_fixed(input, 4)?,
            service_code_hash: Hash32::decode(input)?,
            payload_blob: Octets::decode(input)?,
            refine_gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            accumulate_gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            import_segment_ids: Vec::<ImportInfo>::decode(input)?,
            extrinsic_data_info: Vec::<ExtrinsicInfo>::decode(input)?,
            export_segment_count: u16::decode_fixed(input, 2)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct SegmentRootLookupTable {
    items: HashMap<Hash32, Hash32>,
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
    type Target = HashMap<Hash32, Hash32>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl SegmentRootLookupTable {
    pub fn new(items: HashMap<Hash32, Hash32>) -> Self {
        Self { items }
    }
}

/// Represents a work report generated from refinement of a work package,
/// to be integrated into the on-chain state via the accumulation process.
///
/// In Report (Guarantees) extrinsics, work reports must be ordered by core index in ascending order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkReport {
    /// `s`: Work package availability specification
    pub specs: AvailabilitySpecs,
    /// `x`: Refinement context
    pub refinement_context: RefinementContext,
    /// `c`: Core index on which the work is done
    pub core_index: CoreIndex,
    /// `a`: Authorizer hash
    pub authorizer_hash: Hash32,
    /// **`o`**: Authorization output
    pub authorization_output: Octets,
    /// **`l`**: Segment-root lookup dictionary, up to 8 items
    pub segment_roots_lookup: SegmentRootLookupTable,
    /// **`r`**: Work item results, with at least 1 and no more than 4 items
    pub results: Vec<WorkItemResult>,
}

impl Display for WorkReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "WorkReport {{")?;
        writeln!(f, "\tspec: {}", self.specs)?;
        writeln!(f, "\trefine_ctx: {}", self.refinement_context)?;
        writeln!(f, "\tcore_idx: {}", self.core_index)?;
        writeln!(f, "\tauth_hash: {}", self.authorizer_hash)?;
        writeln!(f, "\tauth_output: {}", self.authorization_output)?;
        writeln!(f, "\tsegment_roots_lookup: {}", self.segment_roots_lookup)?;
        if self.results.is_empty() {
            writeln!(f, "\tresults: []")?;
        } else {
            writeln!(f, "\tresults: [")?;
            for result in self.results.iter() {
                writeln!(f, "\t  {}", result)?;
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
            + self.authorization_output.size_hint()
            + self.segment_roots_lookup.size_hint()
            + self.results.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.specs.encode_to(dest)?;
        self.refinement_context.encode_to(dest)?;
        self.core_index.encode_to_fixed(dest, 2)?; // TODO: check - Not fixed encoding in GP
        self.authorizer_hash.encode_to(dest)?;
        self.authorization_output.encode_to(dest)?;
        self.segment_roots_lookup.encode_to(dest)?;
        self.results.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkReport {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            specs: AvailabilitySpecs::decode(input)?,
            refinement_context: RefinementContext::decode(input)?,
            core_index: CoreIndex::decode_fixed(input, 2)?,
            authorizer_hash: Hash32::decode(input)?,
            authorization_output: Octets::decode(input)?,
            segment_roots_lookup: SegmentRootLookupTable::decode(input)?,
            results: Vec::<WorkItemResult>::decode(input)?,
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
    pub fn hash(&self) -> Result<Hash32, WorkReportError> {
        Ok(hash::<Blake2b256>(self.encode()?.as_slice())?)
    }

    pub fn refinement_context(&self) -> &RefinementContext {
        &self.refinement_context
    }

    pub fn prerequisite(&self) -> &BTreeSet<Hash32> {
        &self.refinement_context.prerequisite_work_packages
    }

    pub fn segment_roots_lookup(&self) -> &HashMap<Hash32, Hash32> {
        &self.segment_roots_lookup
    }

    pub fn work_package_hash(&self) -> Hash32 {
        self.specs.work_package_hash
    }

    pub fn segment_root(&self) -> Hash32 {
        self.specs.segment_root
    }

    pub fn results(&self) -> &[WorkItemResult] {
        &self.results
    }

    pub fn authorization_output(&self) -> &[u8] {
        &self.authorization_output
    }

    pub fn core_index(&self) -> CoreIndex {
        self.core_index
    }

    pub fn authorizer_hash(&self) -> Hash32 {
        self.authorizer_hash
    }

    pub fn total_output_size(&self) -> usize {
        self.authorization_output.len()
            + self
                .results
                .iter()
                .map(|result| result.output_bytes())
                .sum::<usize>()
    }

    pub fn total_accumulation_gas_allotted(&self) -> UnsignedGas {
        self.results
            .iter()
            .map(|result| result.gas_prioritization_ratio)
            .sum()
    }

    pub fn extract_exports_manifest(&self) -> ReportedWorkPackage {
        ReportedWorkPackage {
            work_package_hash: self.specs.work_package_hash,
            segment_root: self.specs.segment_root,
        }
    }
}

/// Context of the blockchain at the point of evaluation of the report's corresponding work-package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefinementContext {
    /// `a`: Anchor block header hash
    pub anchor_header_hash: Hash32,
    /// `s`: Anchor block posterior state root
    pub anchor_state_root: Hash32,
    /// `b`: Anchor block posterior BEEFY root
    pub beefy_root: Hash32,
    /// `l`: Lookup anchor block header hash
    pub lookup_anchor_header_hash: Hash32,
    /// `t`: Lookup anchor block timeslot index
    pub lookup_anchor_timeslot: u32,
    /// **`p`**: Set of prerequisite work package hash
    pub prerequisite_work_packages: BTreeSet<Hash32>,
}

impl Display for RefinementContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "RefineContext: {{ anchor_header_hash: {}, anchor_state_root: {} beefy_root: {}, lookup_anchor_header_hash: {},\
            lookup_anchor_timeslot: {}
        ", self.anchor_header_hash, self.anchor_state_root, self.beefy_root, self.lookup_anchor_header_hash, self.lookup_anchor_timeslot)?;
        if self.prerequisite_work_packages.is_empty() {
            write!(f, "  prerequisites: []}}")?;
        } else {
            write!(f, "  prerequisites: [")?;
            for wp_hash in self.prerequisite_work_packages.iter() {
                write!(f, "    {}", &wp_hash)?;
            }
            write!(f, "  ]}}")?;
        }
        Ok(())
    }
}

impl JamEncode for RefinementContext {
    fn size_hint(&self) -> usize {
        self.anchor_header_hash.size_hint()
            + self.anchor_state_root.size_hint()
            + self.beefy_root.size_hint()
            + self.lookup_anchor_header_hash.size_hint()
            + 4
            + self.prerequisite_work_packages.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.anchor_header_hash.encode_to(dest)?;
        self.anchor_state_root.encode_to(dest)?;
        self.beefy_root.encode_to(dest)?;
        self.lookup_anchor_header_hash.encode_to(dest)?;
        self.lookup_anchor_timeslot.encode_to_fixed(dest, 4)?;
        self.prerequisite_work_packages.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for RefinementContext {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            anchor_header_hash: Hash32::decode(input)?,
            anchor_state_root: Hash32::decode(input)?,
            beefy_root: Hash32::decode(input)?,
            lookup_anchor_header_hash: Hash32::decode(input)?,
            lookup_anchor_timeslot: u32::decode_fixed(input, 4)?,
            prerequisite_work_packages: BTreeSet::<Hash32>::decode(input)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailabilitySpecs {
    /// `h`: Work package hash
    pub work_package_hash: Hash32,
    /// `l`: Auditable work bundle length
    pub work_package_length: u32,
    /// `u`: Erasure root of the work package
    pub erasure_root: Hash32,
    /// `e`: Export segment root of the work package
    pub segment_root: Hash32,
    /// `n`: Number of export segments
    pub segment_count: u16,
}

impl Display for AvailabilitySpecs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AvailSpecs {{ wp_hash: {}, wp_len: {}, erasure_root: {}, \
             segment_root: {}, segment_count: {} }}",
            self.work_package_hash,
            self.work_package_length,
            self.erasure_root,
            self.segment_root,
            self.segment_count,
        )
    }
}

impl JamEncode for AvailabilitySpecs {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + 4
            + self.erasure_root.size_hint()
            + self.segment_root.size_hint()
            + 2
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.work_package_hash.encode_to(dest)?;
        self.work_package_length.encode_to_fixed(dest, 4)?;
        self.erasure_root.encode_to(dest)?;
        self.segment_root.encode_to(dest)?;
        self.segment_count.encode_to_fixed(dest, 2)?;
        Ok(())
    }
}

impl JamDecode for AvailabilitySpecs {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        Ok(Self {
            work_package_hash: Hash32::decode(input)?,
            work_package_length: u32::decode_fixed(input, 4)?,
            erasure_root: Hash32::decode(input)?,
            segment_root: Hash32::decode(input)?,
            segment_count: u16::decode_fixed(input, 2)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItemResult {
    /// `s`: Associated service address
    pub service_index: Address,
    /// `c`: Code hash of the service, at the time of reporting
    pub service_code_hash: Hash32,
    /// `l`: Hash of the associated work item payload
    pub payload_hash: Hash32,
    /// `g`: A ratio to calculate the gas allocated to the work item's accumulation
    pub gas_prioritization_ratio: UnsignedGas,
    /// **`o`**: Output or error of the execution of the work item
    pub refinement_output: WorkExecutionOutput,
}

impl Display for WorkItemResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "WorkItemResult: {{")?;
        writeln!(f, "service_idx: {}", self.service_index)?;
        writeln!(f, "service_code_hash: {}", self.service_code_hash)?;
        writeln!(f, "payload_hash: {}", self.payload_hash)?;
        writeln!(
            f,
            "gas_prioritization_ratio: {}",
            self.gas_prioritization_ratio
        )?;
        writeln!(f, "refine_output: {}", self.refinement_output)?;
        write!(f, "}}")
    }
}

impl JamEncode for WorkItemResult {
    fn size_hint(&self) -> usize {
        4 + self.service_code_hash.size_hint()
            + self.payload_hash.size_hint()
            + 8
            + self.refinement_output.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_index.encode_to_fixed(dest, 4)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_hash.encode_to(dest)?;
        self.gas_prioritization_ratio.encode_to_fixed(dest, 8)?;
        self.refinement_output.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkItemResult {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service_index: Address::decode_fixed(input, 4)?,
            service_code_hash: Hash32::decode(input)?,
            payload_hash: Hash32::decode(input)?,
            gas_prioritization_ratio: UnsignedGas::decode_fixed(input, 8)?,
            refinement_output: WorkExecutionOutput::decode(input)?,
        })
    }
}

impl WorkItemResult {
    fn output_bytes(&self) -> usize {
        match &self.refinement_output {
            WorkExecutionOutput::Output(bytes) => bytes.len(),
            WorkExecutionOutput::Error(_) => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionOutput {
    Output(Octets),
    Error(WorkExecutionError),
}

impl Display for WorkExecutionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Output(octets) => {
                write!(f, "{}", octets)
            }
            Self::Error(err) => {
                write!(f, "{:?}", err)
            }
        }
    }
}

impl JamEncode for WorkExecutionOutput {
    fn size_hint(&self) -> usize {
        match self {
            WorkExecutionOutput::Output(data) => {
                1 + data.size_hint() // with 1 byte prefix
            }
            WorkExecutionOutput::Error(_) => 1, // 1 byte succinct encoding
        }
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        match self {
            WorkExecutionOutput::Output(data) => {
                0u8.encode_to(dest)?; // prefix (0) for Output
                data.encode_to(dest)?;
                Ok(())
            }
            WorkExecutionOutput::Error(error) => match error {
                WorkExecutionError::OutOfGas => 1u8.encode_to(dest),
                WorkExecutionError::Panic => 2u8.encode_to(dest),
                WorkExecutionError::BadExports => 3u8.encode_to(dest),
                WorkExecutionError::Bad => 4u8.encode_to(dest),
                WorkExecutionError::Big => 5u8.encode_to(dest),
            },
        }
    }
}

impl JamDecode for WorkExecutionOutput {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            0 => {
                let data = Octets::decode(input)?;
                Ok(WorkExecutionOutput::Output(data))
            }
            1 => Ok(WorkExecutionOutput::Error(WorkExecutionError::OutOfGas)),
            2 => Ok(WorkExecutionOutput::Error(WorkExecutionError::Panic)),
            3 => Ok(WorkExecutionOutput::Error(WorkExecutionError::BadExports)),
            4 => Ok(WorkExecutionOutput::Error(WorkExecutionError::Bad)),
            5 => Ok(WorkExecutionOutput::Error(WorkExecutionError::Big)),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionOutput prefix".into(),
            )),
        }
    }
}

impl WorkExecutionOutput {
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
