use crate::{
    codec::{
        encode_length_discriminated_field, encode_optional_field,
        size_hint_length_discriminated_field, size_hint_optional_field,
    },
    common::types::{Hash32, Octet, UnsignedGas},
};
use parity_scale_codec::{Encode, Output};

// Structs
pub(crate) struct WorkReport {
    authorizer_hash: Hash32,               // a
    core_index: u32,                       // c; N_C
    authorizer_output: Octet,              // o
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
            + 4 // first 4 bytes of lookup_anchor_timeslot
            + size_hint_optional_field(&self.prerequisite_work_package)
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.anchor_header_hash.encode_to(dest);
        self.anchor_state_root.encode_to(dest);
        self.beefy_root.encode_to(dest);
        self.lookup_anchor_header_hash.encode_to(dest);
        let encoded_timeslot = self.lookup_anchor_timeslot.encode();
        dest.write(&encoded_timeslot[..4]);
        encode_optional_field(&self.prerequisite_work_package, dest);
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
            + 4 // first 4 bytes of work_package_length
            + self.erasure_root.size_hint()
    }

    // Note: segment-root not part of the encoding (GP v0.3.0)
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.work_package_hash.encode_to(dest);
        let encoded_work_package_length = self.work_package_length.encode();
        dest.write(&encoded_work_package_length[..4]);
        self.erasure_root.encode_to(dest);
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
        4 // first 4 bytes of service_index
            + self.service_code_hash.size_hint()
            + self.payload_hash.size_hint()
            + 8 // first 8 bytes of gas_prioritization_ratio
            + self.refinement_output.size_hint()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        let encoded_service_index = self.service_index.encode();
        dest.write(&encoded_service_index[..4]);
        self.service_code_hash.encode_to(dest);
        self.payload_hash.encode_to(dest);
        let encoded_gas_prioritization_ratio = self.gas_prioritization_ratio.encode();
        dest.write(&encoded_gas_prioritization_ratio[..8]);
        self.refinement_output.encode_to(dest);
    }
}

enum RefinementOutput {
    Output(Octet),
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
