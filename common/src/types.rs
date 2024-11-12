use crate::{HASH_SIZE, VALIDATOR_COUNT};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
};

// Type aliases
pub type Hash32 = ByteArray<HASH_SIZE>;
pub type Octets = ByteSequence;
pub type Address = u32; // service account address (index)
pub type ValidatorIndex = u16;
pub type CoreIndex = u16;
pub type Balance = u64;
pub type BandersnatchPubKey = ByteArray<32>;
pub type BandersnatchSignature = ByteArray<96>; // `F` signature type
pub type BandersnatchRingRoot = ByteArray<144>;
pub type BandersnatchRingVrfSignature = Box<ByteArray<784>>; // `F bar` signature type
pub type Ed25519PubKey = ByteArray<32>;
pub type Ed25519SecretKey = ByteArray<32>;
pub type Ed25519Signature = ByteArray<64>;
pub type BlsPubKey = ByteArray<144>;
pub type SignedGas = i64;
pub type UnsignedGas = u64;
pub type ValidatorSet = Box<[ValidatorKey; VALIDATOR_COUNT]>;

// Default values
pub const HASH32_EMPTY: Hash32 = ByteArray([0u8; 32]);
pub const BANDERSNATCH_SIGNATURE_EMPTY: BandersnatchSignature = ByteArray([0u8; 96]);
pub const BANDERSNATCH_RING_ROOT_DEFAULT: BandersnatchRingRoot = ByteArray([0u8; 144]);

// Types
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSequence(pub Vec<u8>);

impl Deref for ByteSequence {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ByteSequence {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl JamEncode for ByteSequence {
    fn size_hint(&self) -> usize {
        self.0.len()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        // By default add length discriminator prefix for octets
        (self.0.len() as u8).encode_to(dest)?;
        dest.write(self.0.as_slice());
        Ok(())
    }
}

impl JamDecode for ByteSequence {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut vec = vec![];
        input
            .read(&mut vec)
            .map_err(|_| JamCodecError::InputError("Failed to Decode ByteSequence".into()))?;
        Ok(Self(vec))
    }
}

impl ByteSequence {
    pub fn new(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn from_vec(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> JamEncode for ByteArray<N> {
    fn size_hint(&self) -> usize {
        N
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        dest.write(&self.0);
        Ok(())
    }
}

impl<const N: usize> JamDecode for ByteArray<N> {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let mut array = [0u8; N];
        input
            .read(&mut array)
            .map_err(|_| JamCodecError::InputError("Failed to decode ByteArray".into()))?;
        Ok(Self(array))
    }
}

impl<const N: usize> ByteArray<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    pub fn encode_hex(&self) -> String {
        hex::encode(self.0)
    }
}

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
#[derive(Debug, Default, Clone, Copy, JamEncode, JamDecode)]
pub struct ValidatorKey {
    pub bandersnatch_key: BandersnatchPubKey,
    pub ed25519_key: Ed25519PubKey,
    pub bls_key: BlsPubKey,
    pub metadata: ByteArray<128>,
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(
            f,
            "  \"Bandersnatch\": \"{}\",",
            self.bandersnatch_key.encode_hex()
        )?;
        writeln!(f, "  \"Ed25519\": \"{}\",", self.ed25519_key.encode_hex())?;
        writeln!(f, "  \"BLS\": \"{}\",", self.bls_key.encode_hex())?;
        writeln!(f, "  \"Metadata\": \"{}\"", self.metadata.encode_hex())?;
        write!(f, "}}")
    }
}

impl ValidatorKey {
    pub fn to_bytes(self) -> ByteArray<336> {
        let mut result = [0u8; 336];

        result[0..32].copy_from_slice(&self.bandersnatch_key.0);
        result[32..64].copy_from_slice(&self.ed25519_key.0);
        result[64..208].copy_from_slice(&self.bls_key.0);
        result[208..336].copy_from_slice(&self.metadata.0);

        ByteArray::new(result)
    }

    pub fn to_json_like(self, indent: usize) -> String {
        let spaces = " ".repeat(indent);
        format!(
            "{s}\"bandersnatch_key\": \"{}\",\n{s}\"ed25519_key\": \"{}\",\n{s}\"bls_key\": \"{}\",\n{s}\"metadata\": \"{}\"",
            self.bandersnatch_key.encode_hex(),
            self.ed25519_key.encode_hex(),
            self.bandersnatch_key.encode_hex(),
            self.metadata.encode_hex(),
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
            "{{ \"id\": \"{}\", \"attempt\": \"{}\" }}",
            self.id.encode_hex(),
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
