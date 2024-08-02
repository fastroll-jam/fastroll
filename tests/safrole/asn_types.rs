use crate::safrole::utils::{deserialize_hex, serialize_hex, AsnTypeError};
use rjam::state::components::{safrole::SlotSealerType, validators::ValidatorKey};
use serde::{Deserialize, Serialize};

// Define constants
pub const VALIDATORS_COUNT: usize = 6;
pub const EPOCH_LENGTH: usize = 12;

// Define basic types
pub type U8 = u8;
pub type U32 = u32;

// Define fixed-length arrays
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ByteArray32(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 32],
);
pub type OpaqueHash = ByteArray32;
pub type Ed25519Key = ByteArray32;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlsKey(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 144],
);
pub type BandersnatchKey = ByteArray32;
pub type EpochKeys = [BandersnatchKey; EPOCH_LENGTH];
pub type TicketsBodies = [TicketBody; EPOCH_LENGTH];

// Define enumerations
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TicketsOrKeys {
    tickets(TicketsBodies),
    keys(EpochKeys),
}

impl TryFrom<SlotSealerType> for TicketsOrKeys {
    type Error = AsnTypeError;

    fn try_from(value: SlotSealerType) -> Result<Self, Self::Error> {
        match value {
            SlotSealerType::Tickets(tickets) => {
                let ticket_bodies: TicketsBodies = tickets
                    .iter()
                    .map(|ticket| TicketBody {
                        id: ByteArray32(ticket.id),
                        attempt: ticket.attempt,
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        AsnTypeError::ConversionError(
                            "Failed to convert tickets to TicketsBodies".to_string(),
                        )
                    })?;

                Ok(TicketsOrKeys::tickets(ticket_bodies))
            }
            SlotSealerType::BandersnatchPubKeys(keys) => {
                let epoch_keys: EpochKeys = keys
                    .iter()
                    .map(|key| ByteArray32(*key))
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| {
                        AsnTypeError::ConversionError(
                            "Failed to convert BandersnatchPubKeys to EpochKeys".to_string(),
                        )
                    })?;

                Ok(TicketsOrKeys::keys(epoch_keys))
            }
        }
    }
}

// State transition function execution error.
// Error codes are not specified in the Graypaper.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CustomErrorCode {
    BadSlot,          // Timeslot value must be strictly monotonic
    UnexpectedTicket, // Received a ticket while in epoch's tail
    BadTicketOrder,   // Tickets must be sorted
    BadTicketProof,   // Invalid ticket ring proof
    BadTicketAttempt, // Invalid ticket attempt value
    Reserved,         // Reserved
    DuplicateTicket,  // Found a ticket duplicate
}

// Define structures
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TicketBody {
    pub id: OpaqueHash,
    pub attempt: U8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidatorData {
    pub bandersnatch: BandersnatchKey,
    pub ed25519: Ed25519Key,
    pub bls: BlsKey,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    pub metadata: [U8; 128],
}

impl From<ValidatorKey> for ValidatorData {
    fn from(value: ValidatorKey) -> Self {
        Self {
            bandersnatch: ByteArray32(value.bandersnatch_key),
            ed25519: ByteArray32(value.ed25519_key),
            bls: BlsKey(value.bls_key),
            metadata: value.metadata,
        }
    }
}

pub type ValidatorsData = [ValidatorData; VALIDATORS_COUNT];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TicketEnvelope {
    attempt: U8,
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    signature: [U8; 784],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EpochMark {
    entropy: OpaqueHash,
    validators: [BandersnatchKey; VALIDATORS_COUNT],
}

pub type TicketsMark = [TicketBody; EPOCH_LENGTH];

// Output markers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputMarks {
    epoch_mark: Option<EpochMark>,     // New epoch signal
    tickets_mark: Option<TicketsMark>, // Tickets signal
}

// State relevant to Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    pub tau: U32,                 // Most recent block's timeslot
    pub eta: [OpaqueHash; 4],     // Entropy accumulator and epochal randomness
    pub lambda: ValidatorsData, // Validator keys and metadata which were active in the prior epoch
    pub kappa: ValidatorsData,  // Validator keys and metadata currently active
    pub gamma_k: ValidatorsData, // Validator keys for the following epoch
    pub iota: ValidatorsData,   // Validator keys and metadata to be drawn from next
    pub gamma_a: Vec<TicketBody>, // Sealing-key contest ticket accumulator; size up to `EPOCH_LENGTH`
    pub gamma_s: TicketsOrKeys,   // Sealing-key series of the current epoch
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
    pub gamma_z: [U8; 144], // Bandersnatch ring commitment
}

// Input for Safrole protocol
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub slot: U32,                      // Current slot
    pub entropy: OpaqueHash, // Per block entropy (originated from block entropy source VRF)
    pub extrinsic: Vec<TicketEnvelope>, // Safrole extrinsic; size up to 16
}

// Output from Safrole protocol
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Output {
    ok(OutputMarks),      // Markers
    err(CustomErrorCode), // Error code (not specified in the Graypaper)
}

// Safrole state transition function execution dump
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Testcase {
    pub input: Input,      // Input
    pub pre_state: State,  // Pre-execution state
    pub output: Output,    // Output
    pub post_state: State, // Post-execution state
}
