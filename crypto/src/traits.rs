use crate::error::CryptoError;
use fr_common::ByteEncodable;

pub trait PublicKey: ByteEncodable {}

pub trait SecretKey: ByteEncodable {
    type PublicKey: PublicKey;
    fn generate() -> Self;
    fn from_seed(seed: &[u8]) -> Result<Self, CryptoError>;
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError>;
}

pub trait Signature: ByteEncodable {
    type PublicKey: PublicKey;
}

pub trait VrfSignature: ByteEncodable {
    type PublicKey: PublicKey;
    type VrfOutput;
    fn output_hash(&self) -> Result<Self::VrfOutput, CryptoError>;
}

#[macro_export]
macro_rules! impl_public_key {
    ($t:ty) => {
        impl PublicKey for $t {}
    };
}

#[macro_export]
macro_rules! impl_signature {
    ($sig:ty, $pk:ty) => {
        impl Signature for $sig {
            type PublicKey = $pk;
        }
    };
}
