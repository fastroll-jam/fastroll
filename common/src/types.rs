use crate::{HASH_SIZE, VALIDATOR_COUNT};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

// Type aliases
pub type Hash32 = [u8; HASH_SIZE];
pub type Octets = Vec<u8>;
pub type Address = u32; // service account address (index)
pub type ValidatorIndex = u16;
pub type CoreIndex = u16;
pub type Balance = u64;
pub type BandersnatchPubKey = [u8; 32];
pub type BandersnatchSignature = [u8; 96]; // `F` signature type
pub type BandersnatchRingRoot = [u8; 144];
pub type BandersnatchRingVrfSignature = Box<[u8; 784]>; // `F bar` signature type
pub type Ed25519PubKey = [u8; 32];
pub type Ed25519SecretKey = [u8; 32];
pub type Ed25519Signature = [u8; 64];
pub type BlsPubKey = [u8; 144];
pub type SignedGas = i64;
pub type UnsignedGas = u64;
pub type ValidatorSet = Box<[ValidatorKey; VALIDATOR_COUNT]>;

// Default values
pub const HASH32_EMPTY: Hash32 = [0u8; 32];
pub const BANDERSNATCH_SIGNATURE_EMPTY: BandersnatchSignature = [0u8; 96];
pub const BANDERSNATCH_RING_ROOT_DEFAULT: BandersnatchRingRoot = [0u8; 144];

// Types

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
    pub bandersnatch_key: BandersnatchPubKey,
    pub ed25519_key: Ed25519PubKey,
    pub bls_key: BlsPubKey,
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
        Self {
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
