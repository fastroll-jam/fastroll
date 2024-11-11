use crate::test_utils::{
    deserialize_hex_array, deserialize_hex_vec, serialize_hex_array, serialize_hex_vec,
};
use rjam_common::{ByteArray, Octets, ValidatorKey, ValidatorSet, VALIDATOR_COUNT};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fmt::{Debug, Display},
};

// Define constants
pub const VALIDATORS_COUNT: usize = 6;
pub const VALIDATORS_SUPER_MAJORITY: usize = 5;
pub const EPOCH_LENGTH: usize = 12;
pub const CORE_COUNT: usize = 2;
// pub const AVAIL_BITFIELD_BYTES: usize = 1; // (CORE_COUNT + 7) / 8

// Define basic types
pub type TimeSlot = u32;
pub type OpaqueHash = ByteArray32;
pub type Ed25519Key = ByteArray32;
pub type Ed25519Signature = ByteArray64;
pub type BandersnatchKey = ByteArray32;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BandersnatchVrfSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 96],
);

impl From<ByteArray<96>> for BandersnatchVrfSignature {
    fn from(value: ByteArray<96>) -> Self {
        Self(value.0)
    }
}

impl Debug for BandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BandersnatchVrfSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BandersnatchRingSignature(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 784],
);

impl From<ByteArray<784>> for BandersnatchRingSignature {
    fn from(value: ByteArray<784>) -> Self {
        Self(value.0)
    }
}

impl Debug for BandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BandersnatchRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct BlsKey(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 144],
);

impl From<ByteArray<144>> for BlsKey {
    fn from(value: ByteArray<144>) -> Self {
        Self(value.0)
    }
}

impl Debug for BlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for BlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ByteSequence(
    #[serde(
        serialize_with = "serialize_hex_vec",
        deserialize_with = "deserialize_hex_vec"
    )]
    pub Octets,
);

impl Debug for ByteSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Display for ByteSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl From<Octets> for ByteSequence {
    fn from(value: Octets) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
pub struct ByteArray32(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 32],
);

impl From<ByteArray<32>> for ByteArray32 {
    fn from(value: ByteArray<32>) -> Self {
        Self(value.0)
    }
}

impl From<[u8; 32]> for ByteArray32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Debug for ByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for ByteArray32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct ByteArray64(
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub [u8; 64],
);

impl From<ByteArray<64>> for ByteArray64 {
    fn from(value: ByteArray<64>) -> Self {
        Self(value.0)
    }
}

impl Debug for ByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Display for ByteArray64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ValidatorData {
    pub bandersnatch: BandersnatchKey,
    pub ed25519: Ed25519Key,
    pub bls: BlsKey,
    #[serde(
        serialize_with = "serialize_hex_array",
        deserialize_with = "deserialize_hex_array"
    )]
    pub metadata: [u8; 128],
}

impl Default for ValidatorData {
    fn default() -> Self {
        Self {
            bandersnatch: ByteArray32::default(),
            ed25519: ByteArray32::default(),
            bls: BlsKey([0u8; 144]),
            metadata: [0u8; 128],
        }
    }
}

impl From<ValidatorKey> for ValidatorData {
    fn from(value: ValidatorKey) -> Self {
        Self {
            bandersnatch: ByteArray32(value.bandersnatch_key.0),
            ed25519: ByteArray32(value.ed25519_key.0),
            bls: BlsKey(value.bls_key.0),
            metadata: value.metadata.0,
        }
    }
}

impl From<ValidatorData> for ValidatorKey {
    fn from(value: ValidatorData) -> Self {
        Self {
            bandersnatch_key: ByteArray::new(value.bandersnatch.0),
            ed25519_key: ByteArray::new(value.ed25519.0),
            bls_key: ByteArray::new(value.bls.0),
            metadata: ByteArray::new(value.metadata),
        }
    }
}

pub type ValidatorsData = [ValidatorData; VALIDATORS_COUNT];

pub fn validators_data_to_validator_set(data: &ValidatorsData) -> ValidatorSet {
    let mut validator_keys = [ValidatorKey::default(); VALIDATOR_COUNT];
    for (i, validator_data) in data.iter().enumerate() {
        validator_keys[i] = ValidatorKey::from(validator_data.clone());
    }

    Box::new(validator_keys)
}

pub fn validator_set_to_validators_data(data: &ValidatorSet) -> ValidatorsData {
    let mut validators_data = ValidatorsData::default();
    for (i, key) in data.into_iter().enumerate() {
        validators_data[i] = ValidatorData::from(key);
    }

    validators_data
}
