use crate::{
    error::CryptoError,
    impl_byte_encodable, impl_signature,
    traits::{Signature, VrfSignature},
    types::{BandersnatchPubKey, Ed25519PubKey},
    vrf::vrf_core::{IetfVrfSignature, RingVrfSignature},
};
use ark_vrf::reexports::ark_serialize::CanonicalDeserialize;
use fr_codec::prelude::*;
use fr_common::{BandersnatchOutputHash, ByteArray, ByteEncodable, CommonTypeError};
use serde::{Deserialize, Serialize};

/// 96-byte Bandersnatch signature type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, JamEncode, JamDecode)]
pub struct BandersnatchSig(pub ByteArray<96>);
impl_byte_encodable!(BandersnatchSig);

impl VrfSignature for BandersnatchSig {
    type PublicKey = BandersnatchPubKey;
    type VrfOutput = BandersnatchOutputHash;

    /// `Y` hash output function for a VRF signature.
    fn output_hash(&self) -> Result<Self::VrfOutput, CryptoError> {
        let sig = IetfVrfSignature::deserialize_compressed(self.as_slice())?;
        Ok(BandersnatchOutputHash::new(sig.output_hash()))
    }
}

/// 784-byte Bandersnatch Ring VRF signature type.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, JamEncode, JamDecode)]
pub struct BandersnatchRingVrfSig(pub Box<ByteArray<784>>);

impl ByteEncodable for BandersnatchRingVrfSig {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    fn from_slice(slice: &[u8]) -> Result<Self, CommonTypeError> {
        Ok(Self(Box::new(ByteArray::from_slice(slice)?)))
    }

    fn from_hex(hex_str: &str) -> Result<Self, CommonTypeError> {
        Ok(Self(Box::new(ByteArray::from_hex(hex_str)?)))
    }
}

impl VrfSignature for BandersnatchRingVrfSig {
    type PublicKey = BandersnatchPubKey;
    type VrfOutput = BandersnatchOutputHash;

    /// `Y` hash output function for an anonymous RingVRF signature.
    fn output_hash(&self) -> Result<Self::VrfOutput, CryptoError> {
        let sig = RingVrfSignature::deserialize_compressed(self.as_slice())?;
        Ok(BandersnatchOutputHash::new(sig.output_hash()))
    }
}

/// 64-byte Ed25519 signature type.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JamEncode,
    JamDecode,
)]
pub struct Ed25519Sig(pub ByteArray<64>);
impl_byte_encodable!(Ed25519Sig);
impl_signature!(Ed25519Sig, Ed25519PubKey);
