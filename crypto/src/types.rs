use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{ByteArray, ValidatorIndex, PUBLIC_KEY_SIZE, VALIDATOR_COUNT};
use std::fmt::{Display, Formatter};

/// 32-byte Bandersnatch public key type.
pub type BandersnatchPubKey = ByteArray<32>;

/// 32-byte Bandersnatch secret key type.
pub type BandersnatchSecretKey = ByteArray<32>;

/// 96-byte Bandersnatch signature type.
/// Represents `F` signature type of the GP.
pub type BandersnatchSig = ByteArray<96>;

/// 144-byte Bandersnatch Ring root type.
pub type BandersnatchRingRoot = ByteArray<144>;

/// 784-byte Bandersnatch Ring VRF signature type.
/// Represents `F bar` signature type of the GP.
pub type BandersnatchRingVrfSig = Box<ByteArray<784>>;

/// 32-byte Ed25519 public key type.
pub type Ed25519PubKey = ByteArray<32>;

/// 32-byte Ed25519 secret key type.
pub type Ed25519SecretKey = ByteArray<32>;

/// 64-byte Ed25519 signature type.
pub type Ed25519Sig = ByteArray<64>;

/// 144-byte BLS public key type.
pub type BlsPubKey = ByteArray<144>;

/// Set of `VALIDATOR_COUNT` validator keys.
pub type ValidatorKeySet = Box<[ValidatorKey; VALIDATOR_COUNT]>;

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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, JamEncode, JamDecode)]
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
    pub fn to_byte_array(self) -> ByteArray<PUBLIC_KEY_SIZE> {
        let mut result = [0u8; PUBLIC_KEY_SIZE];

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

// Util Functions
fn get_validator_key_by_index(
    validator_set: &ValidatorKeySet,
    validator_index: ValidatorIndex,
) -> Option<&ValidatorKey> {
    if validator_index as usize >= VALIDATOR_COUNT {
        return None;
    }
    Some(&validator_set[validator_index as usize])
}

pub fn get_validator_ed25519_key_by_index(
    validator_set: &ValidatorKeySet,
    validator_index: ValidatorIndex,
) -> Option<&Ed25519PubKey> {
    get_validator_key_by_index(validator_set, validator_index).map(|v| &v.ed25519_key)
}
