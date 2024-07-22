use crate::{
    codec::{
        decode_length_discriminated_field, decode_optional_field,
        encode_length_discriminated_field, encode_optional_field,
        size_hint_length_discriminated_field, size_hint_optional_field,
    },
    common::{
        types::{Hash32, Octets, UnsignedGas},
        HASH32_DEFAULT,
    },
};
use parity_scale_codec::{Decode, Encode, Error, Input, Output};

// Structs
pub(crate) struct WorkReport {
    authorizer_hash: Hash32,               // a
    core_index: u32,                       // c; N_C
    authorizer_output: Octets,             // o
    refinement_context: RefinementContext, // x
    specs: AvailabilitySpecifications,     // s
    results: Vec<WorkItemResult>,          // r; length range [1, 4]
}

impl Encode for WorkReport {
    fn size_hint(&self) -> usize {
        self.authorizer_hash.size_hint()
            + self.core_index.size_hint()
            + size_hint_length_discriminated_field(&self.authorizer_output)
            + self.refinement_context.size_hint()
            + self.specs.size_hint()
            + size_hint_length_discriminated_field(&self.results)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.authorizer_hash.encode_to(dest);
        self.core_index.encode_to(dest);
        encode_length_discriminated_field(&self.authorizer_output, dest);
        self.refinement_context.encode_to(dest);
        self.specs.encode_to(dest);
        encode_length_discriminated_field(&self.results, dest);
    }
}

impl Decode for WorkReport {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let authorizer_hash = Hash32::decode(input)?;
        let core_index = u32::decode(input)?;
        let authorizer_output = decode_length_discriminated_field(input)?;
        let refinement_context = RefinementContext::decode(input)?;
        let specs = AvailabilitySpecifications::decode(input)?;
        let results = decode_length_discriminated_field(input)?;

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

struct RefinementContext {
    anchor_header_hash: Hash32,                // a
    anchor_state_root: Hash32,                 // s; posterior state root of the anchor block
    beefy_root: Hash32,                        // b
    lookup_anchor_header_hash: Hash32,         // l
    lookup_anchor_timeslot: u32,               // t
    prerequisite_work_package: Option<Hash32>, // p
}

impl Encode for RefinementContext {
    fn size_hint(&self) -> usize {
        self.anchor_header_hash.size_hint()
            + self.anchor_state_root.size_hint()
            + self.beefy_root.size_hint()
            + self.lookup_anchor_header_hash.size_hint()
            + self.lookup_anchor_timeslot.size_hint()
            + size_hint_optional_field(&self.prerequisite_work_package)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.anchor_header_hash.encode_to(dest);
        self.anchor_state_root.encode_to(dest);
        self.beefy_root.encode_to(dest);
        self.lookup_anchor_header_hash.encode_to(dest);
        self.lookup_anchor_timeslot.encode_to(dest);
        encode_optional_field(&self.prerequisite_work_package, dest);
    }
}

impl Decode for RefinementContext {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let anchor_header_hash = Hash32::decode(input)?;
        let anchor_state_root = Hash32::decode(input)?;
        let beefy_root = Hash32::decode(input)?;
        let lookup_anchor_header_hash = Hash32::decode(input)?;
        let lookup_anchor_timeslot = u32::decode(input)?;
        let prerequisite_work_package = decode_optional_field(input)?;

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

struct AvailabilitySpecifications {
    work_package_hash: Hash32,
    work_package_length: u32, // N_N
    erasure_root: Hash32,
    segment_root: Hash32,
}

impl Encode for AvailabilitySpecifications {
    fn size_hint(&self) -> usize {
        self.work_package_hash.size_hint()
            + self.work_package_length.size_hint()
            + self.erasure_root.size_hint()
    }

    // Note: segment-root not part of the encoding (GP v0.3.0)
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.work_package_hash.encode_to(dest);
        self.work_package_length.encode_to(dest);
        self.erasure_root.encode_to(dest);
    }
}

impl Decode for AvailabilitySpecifications {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
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

struct WorkItemResult {
    service_index: u32,                    // s; N_S
    service_code_hash: Hash32,             // c
    payload_hash: Hash32,                  // l
    gas_prioritization_ratio: UnsignedGas, // g
    refinement_output: RefinementOutput,   // o
}

impl Encode for WorkItemResult {
    fn size_hint(&self) -> usize {
        self.service_index.size_hint()
            + self.service_code_hash.size_hint()
            + self.payload_hash.size_hint()
            + self.gas_prioritization_ratio.size_hint()
            + self.refinement_output.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.service_index.encode_to(dest);
        self.service_code_hash.encode_to(dest);
        self.payload_hash.encode_to(dest);
        self.gas_prioritization_ratio.encode_to(dest);
        self.refinement_output.encode_to(dest);
    }
}

impl Decode for WorkItemResult {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
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

enum RefinementOutput {
    Output(Octets),
    Error(RefinementErrors),
}

enum RefinementErrors {
    OutOfGas,
    UnexpectedTermination,
    ServiceCodeLookupError, // BAD
    CodeSizeExceeded,       // BIG; max size: 4_000_000 octets
}

impl Encode for RefinementOutput {
    fn size_hint(&self) -> usize {
        match self {
            RefinementOutput::Output(data) => {
                1 + size_hint_length_discriminated_field(data) // with 1 byte prefix
            }
            RefinementOutput::Error(_) => 1, // 1 byte succinct encoding
        }
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        match self {
            RefinementOutput::Output(data) => {
                0u8.encode_to(dest); // prefix (0) for Output
                encode_length_discriminated_field(data, dest);
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

impl Decode for RefinementOutput {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        match u8::decode(input)? {
            0 => {
                let data = decode_length_discriminated_field(input)?;
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
            _ => Err(Error::from("Invalid RefinementOutput prefix")),
        }
    }
}

impl Decode for RefinementErrors {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        match u8::decode(input)? {
            1 => Ok(RefinementErrors::OutOfGas),
            2 => Ok(RefinementErrors::UnexpectedTermination),
            3 => Ok(RefinementErrors::ServiceCodeLookupError),
            4 => Ok(RefinementErrors::CodeSizeExceeded),
            _ => Err(Error::from("Invalid RefinementErrors prefix")),
        }
    }
}
