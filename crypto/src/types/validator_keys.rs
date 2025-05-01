use rjam_codec::prelude::*;

use crate::types::{BandersnatchPubKey, BlsPubKey, Ed25519PubKey};
use rjam_common::{ByteArray, ByteEncodable, ValidatorIndex, PUBLIC_KEY_SIZE, VALIDATOR_COUNT};
use std::{
    fmt::{Display, Formatter},
    ops::{Deref, DerefMut},
};

/// 144-byte Bandersnatch Ring root type.
pub type BandersnatchRingRoot = ByteArray<144>;

/// Represents a validator key, composed of 4 distinct components:
/// - Bandersnatch public key (32 bytes)
/// - Ed25519 public key (32 bytes)
/// - BLS public key (144 bytes)
/// - Metadata (128 bytes)
///
/// The total size of a ValidatorKey is 336 bytes, with each component
/// stored as a fixed-size byte array.
///
/// The final `ValidatorKey` type is a simple concatenation of each component.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ValidatorKey {
    // @GP(6.9::type::v0.6.5)
    pub bandersnatch_key: BandersnatchPubKey,
    // @GP(6.10::type::v0.6.5)
    pub ed25519_key: Ed25519PubKey,
    // @GP(6.11::type::v0.6.5)
    pub bls_key: BlsPubKey,
    // @GP(6.12::type::v0.6.5)
    pub metadata: ByteArray<128>,
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(
            f,
            "  \"Bandersnatch\": \"{}\",",
            self.bandersnatch_key.to_hex()
        )?;
        writeln!(f, "  \"Ed25519\": \"{}\",", self.ed25519_key.to_hex())?;
        writeln!(f, "  \"BLS\": \"{}\",", self.bls_key.to_hex())?;
        writeln!(f, "  \"Metadata\": \"{}\"", self.metadata.encode_hex())?;
        write!(f, "}}")
    }
}

impl ValidatorKey {
    pub fn to_byte_array(self) -> ByteArray<PUBLIC_KEY_SIZE> {
        let mut result = [0u8; PUBLIC_KEY_SIZE];

        result[0..32].copy_from_slice(self.bandersnatch_key.as_slice());
        result[32..64].copy_from_slice(self.ed25519_key.as_slice());
        result[64..208].copy_from_slice(self.bls_key.as_slice());
        result[208..336].copy_from_slice(self.metadata.as_slice());

        ByteArray::new(result)
    }

    pub fn to_json_like(self, indent: usize) -> String {
        let spaces = " ".repeat(indent);
        format!(
            "{s}\"bandersnatch_key\": \"{}\",\n{s}\"ed25519_key\": \"{}\",\n{s}\"bls_key\": \"{}\",\n{s}\"metadata\": \"{}\"",
            self.bandersnatch_key.to_hex(),
            self.ed25519_key.to_hex(),
            self.bandersnatch_key.to_hex(),
            self.metadata.encode_hex(),
            s = spaces
        )
    }
}

// @GP(6.8::type::v0.6.5)
/// Set of `VALIDATOR_COUNT` validator keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ValidatorKeySet(pub Box<[ValidatorKey; VALIDATOR_COUNT]>);

impl Deref for ValidatorKeySet {
    type Target = [ValidatorKey; VALIDATOR_COUNT];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ValidatorKeySet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ValidatorKeySet {
    pub fn get_validator_ed25519_key(
        &self,
        validator_index: ValidatorIndex,
    ) -> Option<&Ed25519PubKey> {
        self.get_validator_key(validator_index)
            .map(|v| &v.ed25519_key)
    }

    pub fn get_validator_bandersnatch_key(
        &self,
        validator_index: ValidatorIndex,
    ) -> Option<&BandersnatchPubKey> {
        self.get_validator_key(validator_index)
            .map(|v| &v.bandersnatch_key)
    }

    fn get_validator_key(&self, validator_index: ValidatorIndex) -> Option<&ValidatorKey> {
        if validator_index as usize >= VALIDATOR_COUNT {
            return None;
        }
        Some(&self[validator_index as usize])
    }
}
