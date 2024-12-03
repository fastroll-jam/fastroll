use rjam_codec::{
    JamCodecError, JamDecode, JamDecodeFixed, JamEncode, JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{Address, CoreIndex, Hash32, Octets, UnsignedGas, HASH_SIZE};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    ops::Deref,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkReportError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(Debug, Clone)]
pub enum WorkPackageId {
    SegmentRoot(Hash32),     // h; export segment root
    WorkPackageHash(Hash32), // h with `boxplus` tag; export work package hash
}

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct Authorizer {
    pub auth_code_hash: Hash32, // u
    pub param_blob: Octets,     // p
}

#[derive(Debug, Clone)]
pub struct WorkPackage {
    pub auth_token: Octets,          // j
    pub authorizer_address: Address, // h; service which hosts the authorization code
    pub authorizer: Authorizer,      // u and p
    pub context: RefinementContext,  // x
    pub work_items: Vec<WorkItem>,   // w; length range [1, 4]
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

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub work_package_id: WorkPackageId, // h
    pub item_index: u16,                // i; range [0, 2^15)
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

#[derive(Debug, Clone)]
pub struct ExtrinsicInfo {
    pub blob_hash: Hash32,  // h
    pub blob_length: usize, // i
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
            blob_length: usize::decode(input)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub service_index: Address,                  // s
    pub service_code_hash: Hash32,               // c
    pub payload_blob: Octets,                    // y
    pub gas_limit: UnsignedGas,                  // g
    pub import_segment_ids: Vec<ImportInfo>,     // i; up to 2^11 entries
    pub extrinsic_data_info: Vec<ExtrinsicInfo>, // x;
    pub export_segment_count: usize,             // e; max 2^11
}

impl JamEncode for WorkItem {
    fn size_hint(&self) -> usize {
        4 + self.service_code_hash.size_hint()
            + self.payload_blob.size_hint()
            + 8
            + self.import_segment_ids.size_hint()
            + self.extrinsic_data_info.size_hint()
            + 2
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_index.encode_to_fixed(dest, 4)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_blob.encode_to(dest)?;
        self.gas_limit.encode_to_fixed(dest, 8)?;
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
            gas_limit: UnsignedGas::decode_fixed(input, 8)?,
            import_segment_ids: Vec::<ImportInfo>::decode(input)?,
            extrinsic_data_info: Vec::<ExtrinsicInfo>::decode(input)?,
            export_segment_count: usize::decode_fixed(input, 2)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct SegmentRootLookupTable {
    items: HashMap<Hash32, Hash32>,
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

/// Represents a work report generated from refining a work package, to be integrated into the on-chain state.
///
/// In Report (Guarantees) extrinsics, work reports must be ordered by core index in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkReport {
    pub specs: AvailabilitySpecs,                     // s
    pub refinement_context: RefinementContext,        // x
    pub core_index: CoreIndex,                        // c
    pub authorizer_hash: Hash32,                      // a
    pub authorization_output: Octets,                 // o
    pub segment_roots_lookup: SegmentRootLookupTable, // l; number of items up to 8
    pub results: Vec<WorkItemResult>,                 // r; length range [1, 4]
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
        let mut buf = vec![];
        self.encode_to(&mut buf)?;
        Ok(hash::<Blake2b256>(&buf[..])?)
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinementContext {
    pub anchor_header_hash: Hash32,                   // a
    pub anchor_state_root: Hash32,                    // s; posterior state root of the anchor block
    pub beefy_root: Hash32,                           // b
    pub lookup_anchor_header_hash: Hash32,            // l
    pub lookup_anchor_timeslot: u32,                  // t
    pub prerequisite_work_packages: BTreeSet<Hash32>, // p;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailabilitySpecs {
    pub work_package_hash: Hash32, // h
    pub work_package_length: u32,  // l
    pub erasure_root: Hash32,      // u
    pub segment_root: Hash32,      // e; exports root
    pub segment_count: usize,      // n
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
            work_package_length: u32::decode(input)?,
            erasure_root: Hash32::decode(input)?,
            segment_root: Hash32::decode(input)?,
            segment_count: usize::decode(input)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItemResult {
    pub service_index: Address,                 // s
    pub service_code_hash: Hash32,              // c
    pub payload_hash: Hash32,                   // l
    pub gas_prioritization_ratio: UnsignedGas,  // g
    pub refinement_output: WorkExecutionOutput, // o
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionOutput {
    Output(Octets),            // Y
    Error(WorkExecutionError), // J
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

    pub fn bad() -> Self {
        Self::Error(WorkExecutionError::Bad)
    }

    pub fn big() -> Self {
        Self::Error(WorkExecutionError::Big)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionError {
    OutOfGas,
    Panic, // Panic
    Bad,   // BAD; code or account address not found
    Big,   // BIG; code size exceeds MAX_SERVICE_CODE_SIZE
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
                WorkExecutionError::Bad => 3u8.encode_to(dest),
                WorkExecutionError::Big => 4u8.encode_to(dest),
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
            3 => Ok(WorkExecutionOutput::Error(WorkExecutionError::Bad)),
            4 => Ok(WorkExecutionOutput::Error(WorkExecutionError::Big)),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionOutput prefix".into(),
            )),
        }
    }
}

impl JamDecode for WorkExecutionError {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            1 => Ok(WorkExecutionError::OutOfGas),
            2 => Ok(WorkExecutionError::Panic),
            3 => Ok(WorkExecutionError::Bad),
            4 => Ok(WorkExecutionError::Big),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionError prefix".into(),
            )),
        }
    }
}
