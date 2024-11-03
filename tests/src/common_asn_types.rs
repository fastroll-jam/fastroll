use crate::test_utils::{deserialize_hex, serialize_hex};
use rjam_common::{ValidatorKey, ValidatorSet, VALIDATOR_COUNT};
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

// Define basic types
pub type Ed25519Key = ByteArray32;
pub type Ed25519Signature = ByteArray64;
pub type BandersnatchKey = ByteArray32;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlsKey(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 144],
);

// Define fixed-length arrays
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
pub struct ByteArray32(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 32],
);

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

impl From<[u8; 32]> for ByteArray32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub struct ByteArray64(
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")] pub [u8; 64],
);

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
    #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
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
            bandersnatch: ByteArray32(value.bandersnatch_key),
            ed25519: ByteArray32(value.ed25519_key),
            bls: BlsKey(value.bls_key),
            metadata: value.metadata,
        }
    }
}

impl From<ValidatorData> for ValidatorKey {
    fn from(value: ValidatorData) -> Self {
        Self {
            bandersnatch_key: value.bandersnatch.0,
            ed25519_key: value.ed25519.0,
            bls_key: value.bls.0,
            metadata: value.metadata,
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
