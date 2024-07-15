use crate::common::types::{Hash32, Octet, SignedGas};

// Structs
pub(crate) struct WorkReport {
    authorizer_hash: Hash32,
    authorizer_output: Octet,
    refinement_context: RefinementContext,
    specs: AvailabilitySpecifications,
    results: Vec<WorkItemResult>, // length range [1, 4]
}

struct RefinementContext {
    anchor_header_hash: Hash32,
    anchor_state_root: Hash32, // posterior state root of the anchor block
    beefy_root: Hash32,
    lookup_anchor_header_hash: Hash32,
    lookup_anchor_timeslot: u32,
    prerequisite_work_package: Option<Hash32>,
}

struct AvailabilitySpecifications {
    work_package_hash: Hash32,
    work_package_length: u32, // N_N
    erasure_root: Hash32,
    segment_root: Hash32,
}

struct WorkItemResult {
    service_index: u32, // N_S
    service_code_hash: Hash32,
    payload_hash: Hash32,
    gas_prioritization_ratio: SignedGas,
    refinement_output: RefinementOutput,
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
