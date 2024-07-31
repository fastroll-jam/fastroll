use hex;
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use serde_arrays;
use std::fmt;
use std::fmt::Formatter;

// Helper deserializer to manage `0x` prefix
fn deserialize_hex<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for HexVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a 0x-prefixed hex string with {} bytes", N)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let v = v.strip_prefix("0x").unwrap_or(v);
            let bytes = hex::decode(v).map_err(E::custom)?;
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("Expected {} bytes", N)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

// Helper serializer to manage `0x` prefix
fn serialize_hex<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

// Define constants
const VALIDATORS_COUNT: usize = 6;
const EPOCH_LENGTH: usize = 12;

// Define basic types
type U8 = u8;
type U32 = u32;

// Define fixed-length arrays
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ByteArray32(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 32],
);
type OpaqueHash = ByteArray32;
type Ed25519Key = ByteArray32;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlsKey(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 144],
);
type BandersnatchKey = ByteArray32;
type EpochKeys = [BandersnatchKey; EPOCH_LENGTH];
type TicketsBodies = [TicketBody; EPOCH_LENGTH];

// Define enumerations
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum TicketsOrKeys {
    tickets(TicketsBodies),
    keys(EpochKeys),
}

// State transition function execution error.
// Error codes are not specified in the Graypaper.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum CustomErrorCode {
    BadSlot,          // Timeslot value must be strictly monotonic
    UnexpectedTicket, // Received a ticket while in epoch's tail
    BadTicketOrder,   // Tickets must be sorted
    BadTicketProof,   // Invalid ticket ring proof
    BadTicketAttempt, // Invalid ticket attempt value
    Reserved,         // Reserved
    DuplicateTicket,  // Found a ticket duplicate
}

// Define structures
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct TicketBody {
    id: OpaqueHash,
    attempt: U8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ValidatorData {
    bandersnatch: BandersnatchKey,
    ed25519: Ed25519Key,
    bls: BlsKey,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    metadata: [U8; 128],
}

type ValidatorsData = [ValidatorData; VALIDATORS_COUNT];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct TicketEnvelope {
    attempt: U8,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    signature: [U8; 784],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct EpochMark {
    entropy: OpaqueHash,
    validators: [BandersnatchKey; VALIDATORS_COUNT],
}

type TicketsMark = [TicketBody; EPOCH_LENGTH];

// Output markers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct OutputMarks {
    epoch_mark: Option<EpochMark>,     // New epoch signal
    tickets_mark: Option<TicketsMark>, // Tickets signal
}

// State relevant to Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct State {
    tau: U32,                 // Most recent block's timeslot
    eta: [OpaqueHash; 4],     // Entropy accumulator and epochal randomness
    lambda: ValidatorsData,   // Validator keys and metadata which were active in the prior epoch
    kappa: ValidatorsData,    // Validator keys and metadata currently active
    gamma_k: ValidatorsData,  // Validator keys for the following epoch
    iota: ValidatorsData,     // Validator keys and metadata to be drawn from next
    gamma_a: Vec<TicketBody>, // Sealing-key contest ticket accumulator; size up to `EPOCH_LENGTH`
    gamma_s: TicketsOrKeys,   // Sealing-key series of the current epoch
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    gamma_z: [U8; 144], // Bandersnatch ring commitment
}

// Input for Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Input {
    slot: U32,                      // Current slot
    entropy: OpaqueHash,            // Per block entropy (originated from block entropy source VRF)
    extrinsic: Vec<TicketEnvelope>, // Safrole extrinsic; size up to 16
}

// Output from Safrole protocol
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum Output {
    ok(OutputMarks),      // Markers
    err(CustomErrorCode), // Error code (not specified in the Graypaper)
}

// Safrole state transition function execution dump
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct Testcase {
    input: Input,      // Input
    pre_state: State,  // Pre-execution state
    output: Output,    // Output
    post_state: State, // Post-execution state
}
