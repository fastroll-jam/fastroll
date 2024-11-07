use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, CoreIndex, Hash32, Octets, UnsignedGas};
use rjam_crypto::{hash, Blake2b256, CryptoError};
use std::{cmp::Ordering, collections::HashMap};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkReportError {
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("JamCodec error: {0}")]
    JamCodecError(#[from] JamCodecError),
}

#[derive(JamEncode, JamDecode)]
pub struct Authorizer {
    pub auth_code_hash: Hash32, // c
    pub param_blob: Octets,     // p
}

#[derive(JamEncode, JamDecode)]
pub struct WorkPackage {
    pub auth_token: Octets,          // j
    pub authorizer_address: Address, // h; service which hosts the authorization code
    pub authorizer: Authorizer,      // c and p
    pub context: RefinementContext,  // x
    pub work_items: Vec<WorkItem>,   // w; length range [1, 4]
}

#[derive(JamEncode, JamDecode)]
pub struct ImportInfo {
    pub segments_tree_root: Hash32,
    pub item_index: usize,
}

#[derive(JamEncode, JamDecode)]
pub struct ExtrinsicInfo {
    blob_hash: Hash32,
    blob_length: usize,
}

#[derive(JamEncode, JamDecode)]
pub struct WorkItem {
    service_index: Address,                  // s
    service_code_hash: Hash32,               // c
    payload_blob: Octets,                    // y
    gas_limit: UnsignedGas,                  // g
    import_segment_ids: Vec<ImportInfo>,     // i; up to 2^11 entries
    extrinsic_data_info: Vec<ExtrinsicInfo>, // x;
    export_segment_count: usize,             // e; max 2^11
}

/// Represents a work report generated from refining a work package, to be integrated into the on-chain state.
///
/// In Report (Guarantees) extrinsics, work reports must be ordered by core index in ascending order.
#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct WorkReport {
    specs: AvailabilitySpecs,                      // s
    refinement_context: RefinementContext,         // x
    core_index: CoreIndex,                         // c
    authorizer_hash: Hash32,                       // a
    authorization_output: Octets,                  // o
    segment_roots_lookup: HashMap<Hash32, Hash32>, // l; number of items up to 8
    results: Vec<WorkItemResult>,                  // r; length range [1, 4]
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

    pub fn prerequisite(&self) -> Option<Hash32> {
        self.refinement_context.prerequisite_work_package
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

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct RefinementContext {
    pub anchor_header_hash: Hash32,                // a
    pub anchor_state_root: Hash32,                 // s; posterior state root of the anchor block
    pub beefy_root: Hash32,                        // b
    pub lookup_anchor_header_hash: Hash32,         // l
    pub lookup_anchor_timeslot: u32,               // t
    pub prerequisite_work_package: Option<Hash32>, // p
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvailabilitySpecs {
    work_package_hash: Hash32, // h
    work_package_length: u32,  // l
    erasure_root: Hash32,      // u
    segment_root: Hash32,      // e; exports root
}

impl JamEncode for AvailabilitySpecs {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + self.work_package_length.size_hint()
            + self.erasure_root.size_hint()
            + self.segment_root.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.work_package_hash.encode_to(dest)?;
        self.work_package_length.encode_to(dest)?;
        self.erasure_root.encode_to(dest)?;
        self.segment_root.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AvailabilitySpecs {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let work_package_hash = Hash32::decode(input)?;
        let work_package_length = u32::decode(input)?;
        let erasure_root = Hash32::decode(input)?;
        let segment_root = Hash32::decode(input)?;

        Ok(AvailabilitySpecs {
            work_package_hash,
            work_package_length,
            erasure_root,
            segment_root,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, JamEncode, JamDecode)]
pub struct WorkItemResult {
    pub service_index: Address,                 // s
    pub service_code_hash: Hash32,              // c
    pub payload_hash: Hash32,                   // l
    pub gas_prioritization_ratio: UnsignedGas,  // g
    pub refinement_output: WorkExecutionOutput, // o
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionOutput {
    Output(Octets),            // Y
    Error(WorkExecutionError), // J
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkExecutionError {
    OutOfGas,
    UnexpectedTermination,  // Panic
    ServiceCodeLookupError, // BAD
    CodeSizeExceeded,       // BIG; exceeds MAX_SERVICE_CODE_SIZE
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
                WorkExecutionError::UnexpectedTermination => 2u8.encode_to(dest),
                WorkExecutionError::ServiceCodeLookupError => 3u8.encode_to(dest),
                WorkExecutionError::CodeSizeExceeded => 4u8.encode_to(dest),
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
            2 => Ok(WorkExecutionOutput::Error(
                WorkExecutionError::UnexpectedTermination,
            )),
            3 => Ok(WorkExecutionOutput::Error(
                WorkExecutionError::ServiceCodeLookupError,
            )),
            4 => Ok(WorkExecutionOutput::Error(
                WorkExecutionError::CodeSizeExceeded,
            )),
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
            2 => Ok(WorkExecutionError::UnexpectedTermination),
            3 => Ok(WorkExecutionError::ServiceCodeLookupError),
            4 => Ok(WorkExecutionError::CodeSizeExceeded),
            _ => Err(JamCodecError::InputError(
                "Invalid WorkExecutionError prefix".into(),
            )),
        }
    }
}
