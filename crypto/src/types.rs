use crate::{
    impl_public_key,
    traits::{PublicKey, SecretKey},
};
use ark_vrf::{
    reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    suites::bandersnatch::Secret as ArkSecret,
};
use rand::{rngs::OsRng, RngCore};
use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{
    ByteArray, ByteEncodable, CommonTypeError, ValidatorIndex, PUBLIC_KEY_SIZE, VALIDATOR_COUNT,
};
use std::fmt::{Display, Formatter};

/// Used for deriving `ByteEncodable` for `ByteArray<N>` wrapper newtypes.
macro_rules! impl_byte_encodable {
    ($t:ty) => {
        impl ByteEncodable for $t {
            fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
            fn as_hex(&self) -> String {
                self.0.as_hex()
            }
            fn from_slice(slice: &[u8]) -> Result<Self, CommonTypeError> {
                Ok(Self(ByteArray::from_slice(slice)?))
            }
            fn from_hex(hex_str: &str) -> Result<Self, CommonTypeError> {
                Ok(Self(ByteArray::from_hex(hex_str)?))
            }
        }
    };
}

/// 32-byte Bandersnatch public key type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BandersnatchPubKey(pub ByteArray<32>);
impl_byte_encodable!(BandersnatchPubKey);
impl_public_key!(BandersnatchPubKey);

/// 32-byte Bandersnatch secret key type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, JamEncode, JamDecode)]
pub struct BandersnatchSecretKey(ByteArray<32>);
impl_byte_encodable!(BandersnatchSecretKey);

impl SecretKey for BandersnatchSecretKey {
    type PublicKey = BandersnatchPubKey;

    // TODO: generic rng
    fn generate() -> Self {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        Self(ByteArray(buf))
    }

    fn from_seed(seed: &[u8]) -> Self {
        let ark_secret = ArkSecret::from_seed(seed);
        let mut buf = Vec::with_capacity(32);
        ark_secret.scalar.serialize_compressed(&mut buf).unwrap();
        Self::from_slice(&buf).unwrap()
    }

    fn public_key(&self) -> Self::PublicKey {
        let ark_public = ArkSecret::deserialize_compressed(self.as_slice())
            .unwrap()
            .public();
        let mut buf = Vec::with_capacity(32);
        ark_public.serialize_compressed(&mut buf).unwrap();
        Self::PublicKey::from_slice(&buf).unwrap()
    }
}

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
            self.bandersnatch_key.as_hex()
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
            self.bandersnatch_key.as_hex(),
            self.ed25519_key.encode_hex(),
            self.bandersnatch_key.as_hex(),
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
