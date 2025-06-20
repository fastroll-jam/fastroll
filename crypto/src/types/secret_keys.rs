use crate::{
    impl_byte_encodable,
    traits::SecretKey,
    types::{public_keys::BandersnatchPubKey, Ed25519PubKey},
};
use ark_vrf::{
    reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    suites::bandersnatch::Secret as ArkSecret,
};
use fr_common::{ByteArray, ByteEncodable, CommonTypeError};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte Bandersnatch secret key type.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BandersnatchSecretKey(pub ByteArray<32>);
impl_byte_encodable!(BandersnatchSecretKey);

impl SecretKey for BandersnatchSecretKey {
    type PublicKey = BandersnatchPubKey;

    // TODO: Crypto: generic rng
    fn generate() -> Self {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let sk = Self(ByteArray(buf));
        buf.zeroize();
        sk
    }

    fn from_seed(seed: &[u8]) -> Self {
        let ark_secret = ArkSecret::from_seed(seed);
        let mut buf = Vec::with_capacity(32);
        ark_secret.scalar.serialize_compressed(&mut buf).unwrap();
        let sk = Self::from_slice(&buf).unwrap();
        buf.zeroize();
        sk
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

/// 32-byte Ed25519 secret key type.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey(pub ByteArray<32>);
impl_byte_encodable!(Ed25519SecretKey);

impl SecretKey for Ed25519SecretKey {
    type PublicKey = Ed25519PubKey;

    // TODO: Crypto: generic rng
    fn generate() -> Self {
        let mut rng = OsRng;
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let sk = Self(ByteArray(buf));
        buf.zeroize();
        sk
    }

    fn from_seed(_seed: &[u8]) -> Self {
        unimplemented!()
    }

    fn public_key(&self) -> Self::PublicKey {
        unimplemented!()
    }
}
