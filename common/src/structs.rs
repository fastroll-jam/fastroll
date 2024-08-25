use crate::{
    types::{Hash32, Octets, UnsignedGas},
    HASH32_DEFAULT,
};
use jam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

// Structs

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
#[derive(Copy, Clone, Debug)]
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

impl JamEncode for ValidatorKey {
    fn size_hint(&self) -> usize {
        self.bandersnatch_key.size_hint()
            + self.ed25519_key.size_hint()
            + self.bls_key.size_hint()
            + self.metadata.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.bandersnatch_key.encode_to(dest)?;
        self.ed25519_key.encode_to(dest)?;
        self.bls_key.encode_to(dest)?;
        self.metadata.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for ValidatorKey {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            bandersnatch_key: JamDecode::decode(input)?,
            ed25519_key: JamDecode::decode(input)?,
            bls_key: JamDecode::decode(input)?,
            metadata: JamDecode::decode(input)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ticket {
    pub id: Hash32,  // ticket identifier; `Y` hash of the RingVRF proof
    pub attempt: u8, // `N_N`; 0 or 1
}

impl Default for Ticket {
    fn default() -> Self {
        Self {
            id: HASH32_DEFAULT,
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

impl JamEncode for Ticket {
    fn size_hint(&self) -> usize {
        self.id.size_hint() + self.attempt.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.id.encode_to(dest)?;
        self.attempt.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for Ticket {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            id: Hash32::decode(input)?,
            attempt: u8::decode(input)?,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct WorkReport {
    authorizer_hash: Hash32,               // a
    core_index: u32,                       // c; N_C
    authorizer_output: Octets,             // o
    refinement_context: RefinementContext, // x
    specs: AvailabilitySpecifications,     // s
    results: Vec<WorkItemResult>,          // r; length range [1, 4]
}

impl JamEncode for WorkReport {
    fn size_hint(&self) -> usize {
        self.authorizer_hash.size_hint()
            + self.core_index.size_hint()
            + self.authorizer_output.size_hint()
            + self.refinement_context.size_hint()
            + self.specs.size_hint()
            + self.results.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.authorizer_hash.encode_to(dest)?;
        self.core_index.encode_to(dest)?;
        self.authorizer_output.encode_to(dest)?;
        self.refinement_context.encode_to(dest)?;
        self.specs.encode_to(dest)?;
        self.results.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkReport {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let authorizer_hash = Hash32::decode(input)?;
        let core_index = u32::decode(input)?;
        let authorizer_output = Vec::decode(input)?;
        let refinement_context = RefinementContext::decode(input)?;
        let specs = AvailabilitySpecifications::decode(input)?;
        let results = Vec::decode(input)?;

        Ok(WorkReport {
            authorizer_hash,
            core_index,
            authorizer_output,
            refinement_context,
            specs,
            results,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
struct RefinementContext {
    anchor_header_hash: Hash32,                // a
    anchor_state_root: Hash32,                 // s; posterior state root of the anchor block
    beefy_root: Hash32,                        // b
    lookup_anchor_header_hash: Hash32,         // l
    lookup_anchor_timeslot: u32,               // t
    prerequisite_work_package: Option<Hash32>, // p
}

impl JamEncode for RefinementContext {
    fn size_hint(&self) -> usize {
        self.anchor_header_hash.size_hint()
            + self.anchor_state_root.size_hint()
            + self.beefy_root.size_hint()
            + self.lookup_anchor_header_hash.size_hint()
            + self.lookup_anchor_timeslot.size_hint()
            + self.prerequisite_work_package.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.anchor_header_hash.encode_to(dest)?;
        self.anchor_state_root.encode_to(dest)?;
        self.beefy_root.encode_to(dest)?;
        self.lookup_anchor_header_hash.encode_to(dest)?;
        self.lookup_anchor_timeslot.encode_to(dest)?;
        self.prerequisite_work_package.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for RefinementContext {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let anchor_header_hash = Hash32::decode(input)?;
        let anchor_state_root = Hash32::decode(input)?;
        let beefy_root = Hash32::decode(input)?;
        let lookup_anchor_header_hash = Hash32::decode(input)?;
        let lookup_anchor_timeslot = u32::decode(input)?;
        let prerequisite_work_package = Option::decode(input)?;

        Ok(RefinementContext {
            anchor_header_hash,
            anchor_state_root,
            beefy_root,
            lookup_anchor_header_hash,
            lookup_anchor_timeslot,
            prerequisite_work_package,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
struct AvailabilitySpecifications {
    work_package_hash: Hash32,
    work_package_length: u32, // N_N
    erasure_root: Hash32,
    segment_root: Hash32,
}

impl JamEncode for AvailabilitySpecifications {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + self.work_package_length.size_hint()
            + self.erasure_root.size_hint()
    }

    // Note: segment-root not part of the encoding (GP v0.3.0)
    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.work_package_hash.encode_to(dest)?;
        self.work_package_length.encode_to(dest)?;
        self.erasure_root.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for AvailabilitySpecifications {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let work_package_hash = Hash32::decode(input)?;
        let work_package_length = u32::decode(input)?;
        let erasure_root = Hash32::decode(input)?;
        let segment_root = HASH32_DEFAULT; // Default value since it is not part of the encoding

        Ok(AvailabilitySpecifications {
            work_package_hash,
            work_package_length,
            erasure_root,
            segment_root,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
struct WorkItemResult {
    service_index: u32,                    // s; N_S
    service_code_hash: Hash32,             // c
    payload_hash: Hash32,                  // l
    gas_prioritization_ratio: UnsignedGas, // g
    refinement_output: RefinementOutput,   // o
}

impl JamEncode for WorkItemResult {
    fn size_hint(&self) -> usize {
        self.service_index.size_hint()
            + self.service_code_hash.size_hint()
            + self.payload_hash.size_hint()
            + self.gas_prioritization_ratio.size_hint()
            + self.refinement_output.size_hint()
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        self.service_index.encode_to(dest)?;
        self.service_code_hash.encode_to(dest)?;
        self.payload_hash.encode_to(dest)?;
        self.gas_prioritization_ratio.encode_to(dest)?;
        self.refinement_output.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for WorkItemResult {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        let service_index = u32::decode(input)?;
        let service_code_hash = Hash32::decode(input)?;
        let payload_hash = Hash32::decode(input)?;
        let gas_prioritization_ratio = UnsignedGas::decode(input)?;
        let refinement_output = RefinementOutput::decode(input)?;

        Ok(WorkItemResult {
            service_index,
            service_code_hash,
            payload_hash,
            gas_prioritization_ratio,
            refinement_output,
        })
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
enum RefinementOutput {
    Output(Octets),
    Error(RefinementErrors),
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
enum RefinementErrors {
    OutOfGas,
    UnexpectedTermination,
    ServiceCodeLookupError, // BAD
    CodeSizeExceeded,       // BIG; max size: 4_000_000 octets
}

impl JamEncode for RefinementOutput {
    fn size_hint(&self) -> usize {
        match self {
            RefinementOutput::Output(data) => {
                1 + data.size_hint() // with 1 byte prefix // TODO: check using 1-bit prefix instead
            }
            RefinementOutput::Error(_) => 1, // 1 byte succinct encoding
        }
    }

    fn encode_to<W: JamOutput>(&self, dest: &mut W) -> Result<(), JamCodecError> {
        match self {
            RefinementOutput::Output(data) => {
                0u8.encode_to(dest)?; // prefix (0) for Output
                data.encode_to(dest)?;
                Ok(())
            }
            RefinementOutput::Error(error) => match error {
                RefinementErrors::OutOfGas => 1u8.encode_to(dest),
                RefinementErrors::UnexpectedTermination => 2u8.encode_to(dest),
                RefinementErrors::ServiceCodeLookupError => 3u8.encode_to(dest),
                RefinementErrors::CodeSizeExceeded => 4u8.encode_to(dest),
            },
        }
    }
}

impl JamDecode for RefinementOutput {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            0 => {
                let data = Octets::decode(input)?;
                Ok(RefinementOutput::Output(data))
            }
            1 => Ok(RefinementOutput::Error(RefinementErrors::OutOfGas)),
            2 => Ok(RefinementOutput::Error(
                RefinementErrors::UnexpectedTermination,
            )),
            3 => Ok(RefinementOutput::Error(
                RefinementErrors::ServiceCodeLookupError,
            )),
            4 => Ok(RefinementOutput::Error(RefinementErrors::CodeSizeExceeded)),
            _ => Err(JamCodecError::InputError(
                "Invalid RefinementOutput prefix".into(),
            )),
        }
    }
}

impl JamDecode for RefinementErrors {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError> {
        match u8::decode(input)? {
            1 => Ok(RefinementErrors::OutOfGas),
            2 => Ok(RefinementErrors::UnexpectedTermination),
            3 => Ok(RefinementErrors::ServiceCodeLookupError),
            4 => Ok(RefinementErrors::CodeSizeExceeded),
            _ => Err(JamCodecError::InputError(
                "Invalid RefinementErrors prefix".into(),
            )),
        }
    }
}
