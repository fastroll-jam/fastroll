use rjam_common::ByteEncodable;

pub trait PublicKey: ByteEncodable {}

pub trait SecretKey: ByteEncodable {
    type PublicKey;
    fn generate() -> Self;
    fn from_seed(seed: &[u8]) -> Self;
    fn public_key(&self) -> Self::PublicKey;
}

pub trait Signature: ByteEncodable {
    type PublicKey;
}

pub trait VrfSignature: ByteEncodable {
    type PublicKey;
    type VrfOutput;
    fn output_hash(&self) -> Self::VrfOutput;
}
