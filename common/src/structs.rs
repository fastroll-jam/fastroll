use crate::{
    types::{Hash32, Octets, UnsignedGas},
    AccountAddress, TokenBalance, HASH32_EMPTY, TRANSFER_MEMO_SIZE,
};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

/// Represents a validator key, composed of 4 distinct components:
/// - Bandersnatch public key (32 bytes)
/// - Ed25519 public key (32 bytes)
/// - BLS public key (144 bytes)
/// - Metadata (128 bytes)
///
/// The total size of a ValidatorKey is 336 bytes, with each component
/// stored as a fixed-size byte array.
///
/// The final ValidatorKey type is a simple concatenation of each component.
#[derive(Debug, Clone, Copy, JamEncode, JamDecode)]
pub struct ValidatorKey {
    pub bandersnatch_key: [u8; 32],
    pub ed25519_key: [u8; 32],
    pub bls_key: [u8; 144],
    pub metadata: [u8; 128],
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Bandersnatch key: {}",
            hex::encode(self.bandersnatch_key)
        )?;
        writeln!(f, "Ed25519 key: {}", hex::encode(self.ed25519_key))?;
        writeln!(f, "BLS key: {}", hex::encode(self.bls_key))?;
        write!(f, "Metadata: {}", hex::encode(self.metadata))
    }
}

impl Default for ValidatorKey {
    fn default() -> Self {
        ValidatorKey {
            bandersnatch_key: [0u8; 32],
            ed25519_key: [0u8; 32],
            bls_key: [0u8; 144],
            metadata: [0u8; 128],
        }
    }
}

impl ValidatorKey {
    pub fn to_bytes(self) -> [u8; 336] {
        let mut result = [0u8; 336];

        result[0..32].copy_from_slice(&self.bandersnatch_key);
        result[32..64].copy_from_slice(&self.ed25519_key);
        result[64..208].copy_from_slice(&self.bls_key);
        result[208..336].copy_from_slice(&self.metadata);

        result
    }

    pub fn to_json_like(self, indent: usize) -> String {
        let spaces = " ".repeat(indent);
        format!(
            "{s}\"bandersnatch_key\": \"{}\",\n{s}\"ed25519_key\": \"{}\",\n{s}\"bls_key\": \"{}\",\n{s}\"metadata\": \"{}\"",
            hex::encode(self.bandersnatch_key),
            hex::encode(self.ed25519_key),
            hex::encode(self.bls_key),
            hex::encode(self.metadata),
            s = spaces
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, JamEncode, JamDecode)]
pub struct Ticket {
    pub id: Hash32,  // ticket identifier; `Y` hash of the RingVRF proof
    pub attempt: u8, // `N_N`; 0 or 1
}

impl Default for Ticket {
    fn default() -> Self {
        Self {
            id: HASH32_EMPTY,
            attempt: 0,
        }
    }
}

impl Display for Ticket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Ticket {{ id: {}, attempt: {} }}",
            hex::encode(self.id),
            self.attempt
        )
    }
}

impl PartialOrd for Ticket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ticket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

#[derive(JamEncode)]
pub struct WorkPackage {
    pub auth_token: Octets,                 // j
    pub authorizer_address: AccountAddress, // h; service which hosts the authorization code
    pub auth_code_hash: Hash32,             // c
    pub param_blob: Octets,                 // p
    pub context: RefinementContext,         // x
    pub work_items: Vec<WorkItem>,          // w; length range [1, 4]
}

#[derive(JamEncode)]
pub struct WorkItem {
    service_index: AccountAddress,             // s
    service_code_hash: Hash32,                 // c
    payload_blob: Octets,                      // y
    gas_limit: UnsignedGas,                    // g
    import_segment_ids: Vec<(Hash32, usize)>, // i; [(segments_tree_root, item_index)], up to 2^11 entries
    extrinsic_data_info: Vec<(Hash32, usize)>, // x; [(blob_hash, blob_length)]
    export_segment_count: usize,              // e; max 2^11
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct WorkReport {
    authorizer_hash: Hash32,               // a
    core_index: u32,                       // c; N_C
    authorization_output: Octets,          // o
    refinement_context: RefinementContext, // x
    specs: AvailabilitySpecs,              // s
    results: Vec<WorkItemResult>,          // r; length range [1, 4]
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct RefinementContext {
    pub anchor_header_hash: Hash32,                // a
    pub anchor_state_root: Hash32,                 // s; posterior state root of the anchor block
    pub beefy_root: Hash32,                        // b
    pub lookup_anchor_header_hash: Hash32,         // l
    pub lookup_anchor_timeslot: u32,               // t
    pub prerequisite_work_package: Option<Hash32>, // p
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
struct AvailabilitySpecs {
    work_package_hash: Hash32,
    work_package_length: u32, // N_N
    erasure_root: Hash32,
    segment_root: Hash32,
}

impl JamEncode for AvailabilitySpecs {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + self.work_package_length.size_hint()
            + self.erasure_root.size_hint()
    }

    // FIXME: segment-root not part of the encoding (GP v0.3.0)
    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.work_package_hash.encode_to(dest)?;
        self.work_package_length.encode_to(dest)?;
        self.erasure_root.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AvailabilitySpecs {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let work_package_hash = Hash32::decode(input)?;
        let work_package_length = u32::decode(input)?;
        let erasure_root = Hash32::decode(input)?;
        let segment_root = HASH32_EMPTY; // Default value since it is not part of the encoding

        Ok(AvailabilitySpecs {
            work_package_hash,
            work_package_length,
            erasure_root,
            segment_root,
        })
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct WorkItemResult {
    service_index: AccountAddress,          // s; N_S
    service_code_hash: Hash32,              // c
    payload_hash: Hash32,                   // l
    gas_prioritization_ratio: UnsignedGas,  // g
    refinement_output: WorkExecutionOutput, // o
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum WorkExecutionOutput {
    Output(Octets),            // Y
    Error(WorkExecutionError), // J
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum WorkExecutionError {
    OutOfGas,
    UnexpectedTermination,
    ServiceCodeLookupError, // BAD
    CodeSizeExceeded,       // BIG; exceeds MAX_SERVICE_CODE_SIZE
}

impl JamEncode for WorkExecutionOutput {
    fn size_hint(&self) -> usize {
        match self {
            WorkExecutionOutput::Output(data) => {
                1 + data.size_hint() // with 1 byte prefix // TODO: check using 1-bit prefix instead
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

#[derive(Clone, Copy, JamEncode)]
pub struct DeferredTransfer {
    pub from: AccountAddress,           // s
    pub to: AccountAddress,             // d
    pub amount: TokenBalance,           // a
    pub memo: [u8; TRANSFER_MEMO_SIZE], // m
    pub gas_limit: UnsignedGas,         // g
}
