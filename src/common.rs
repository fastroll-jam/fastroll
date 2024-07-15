// Constants
pub const VALIDATOR_COUNT: usize = 1023; // 1023 validators
pub const FLOOR_TWO_THIRDS_VALIDATOR_COUNT: usize = 2 * VALIDATOR_COUNT / 3; // 682 validators
pub const EPOCH_LENGTH: usize = 600; // 600 timeslots per epoch
pub const CORE_COUNT: usize = 341; // (1023 / 3 = 341) cores

// Types
pub type Hash32 = [u8; 32]; // FIXME: should be subset of `[u8; 32]`
pub type Octet = Vec<u8>;
pub type BandersnatchPubKey = Hash32;
pub type BandersnatchSignature = [u8; 64];
pub type BandersnatchRingRoot = [u8; 196608];
pub type BandersnatchRingVrfProof = [u8; 784];
pub type Ed25519PubKey = Hash32;
pub type Ed25519Signature = [u8; 64];
pub type Ed25519SignatureWithKeyAndMessage = Ed25519Signature;
pub type Ticket = (Hash32, u8); // u8 range [0, 2)
pub type SignedGas = i64;

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
