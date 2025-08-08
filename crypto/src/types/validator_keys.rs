use fr_codec::prelude::*;

use crate::{
    impl_byte_encodable,
    types::{BandersnatchPubKey, BlsPubKey, Ed25519PubKey},
};
use fr_common::{
    ByteArray, ByteEncodable, CommonTypeError, ValidatorIndex, PUBLIC_KEY_SIZE, VALIDATOR_COUNT,
};
use fr_limited_vec::FixedVec;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::{Ipv6Addr, SocketAddrV6},
    ops::{Deref, DerefMut},
};

/// 144-byte Bandersnatch Ring root type.
pub type BandersnatchRingRoot = ByteArray<144>;

/// 128-byte validator metadata.
#[derive(
    Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize, JamEncode, JamDecode,
)]
pub struct ValidatorMetadata(pub ByteArray<128>);
impl_byte_encodable!(ValidatorMetadata);

impl Deref for ValidatorMetadata {
    type Target = ByteArray<128>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ValidatorMetadata {
    pub fn socket_address(&self) -> SocketAddrV6 {
        let ipv6: [u8; 16] = self[0..16]
            .try_into()
            .expect("Should have more than 16 bytes");
        // Decode LE-encoded port number
        let port = u16::decode_fixed(&mut &self[16..18], 2)
            .expect("Should success to decode 2 bytes into u16");
        SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0)
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
/// The final `ValidatorKey` type is a simple concatenation of each component.
#[derive(
    Debug, Clone, Hash, Default, PartialEq, Eq, Serialize, Deserialize, JamEncode, JamDecode,
)]
pub struct ValidatorKey {
    pub bandersnatch: BandersnatchPubKey,
    pub ed25519: Ed25519PubKey,
    pub bls: BlsPubKey,
    pub metadata: ValidatorMetadata,
}

impl Display for ValidatorKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        writeln!(
            f,
            "  \"Bandersnatch\": \"0x{}\",",
            self.bandersnatch.to_hex()
        )?;
        writeln!(f, "  \"Ed25519\": \"0x{}\",", self.ed25519.to_hex())?;
        writeln!(f, "  \"BLS\": \"0x{}\",", self.bls.to_hex())?;
        writeln!(f, "  \"Metadata\": \"0x{}\"", self.metadata.encode_hex())?;
        write!(f, "}}")
    }
}

impl ValidatorKey {
    pub fn to_byte_array(self) -> ByteArray<PUBLIC_KEY_SIZE> {
        let mut result = [0u8; PUBLIC_KEY_SIZE];

        result[0..32].copy_from_slice(self.bandersnatch.as_slice());
        result[32..64].copy_from_slice(self.ed25519.as_slice());
        result[64..208].copy_from_slice(self.bls.as_slice());
        result[208..336].copy_from_slice(self.metadata.as_slice());

        ByteArray::new(result)
    }

    pub fn to_json_like(self, indent: usize) -> String {
        let spaces = " ".repeat(indent);
        format!(
            "{s}\"bandersnatch_key\": \"{}\",\n{s}\"ed25519_key\": \"{}\",\n{s}\"bls_key\": \"{}\",\n{s}\"metadata\": \"{}\"",
            self.bandersnatch.to_hex(),
            self.ed25519.to_hex(),
            self.bandersnatch.to_hex(),
            self.metadata.encode_hex(),
            s = spaces
        )
    }
}

pub type ValidatorKeys = FixedVec<ValidatorKey, VALIDATOR_COUNT>;

/// Set of `VALIDATOR_COUNT` validator keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct ValidatorKeySet(pub ValidatorKeys);

impl Deref for ValidatorKeySet {
    type Target = ValidatorKeys;
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
        self.get_validator_key(validator_index).map(|v| &v.ed25519)
    }

    pub fn get_validator_bandersnatch_key(
        &self,
        validator_index: ValidatorIndex,
    ) -> Option<&BandersnatchPubKey> {
        self.get_validator_key(validator_index)
            .map(|v| &v.bandersnatch)
    }

    fn get_validator_key(&self, validator_index: ValidatorIndex) -> Option<&ValidatorKey> {
        if validator_index as usize >= VALIDATOR_COUNT {
            return None;
        }
        Some(&self[validator_index as usize])
    }

    pub fn get_validator_index(
        &self,
        bandersnatch_key: &BandersnatchPubKey,
    ) -> Option<ValidatorIndex> {
        self.iter()
            .position(|k| &k.bandersnatch == bandersnatch_key)
            .map(|i| i as ValidatorIndex)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_socket_addr_from_metadata() {
        let mut ipv6 = [0u8; 16];
        ipv6[15] = 1;
        let port = 9990;
        let expected_socket_addr = SocketAddrV6::new(Ipv6Addr::from(ipv6), port, 0, 0);
        let metadata = ValidatorMetadata::from_hex("0x0000000000000000000000000000000106270000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let socket_addr = metadata.socket_address();
        assert_eq!(expected_socket_addr, socket_addr);
    }
}
