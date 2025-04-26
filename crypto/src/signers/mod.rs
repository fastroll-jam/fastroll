pub mod bls;
pub mod ed25519;

/// Used for Ed25519, BLS keys.
pub trait Signer {
    type SecretKey;
    type Signature;
    fn new(key: Self::SecretKey) -> Self;
    fn sign_message(&self, message: &[u8]) -> Self::Signature;
}

/// Used for Ed25519, BLS keys.
pub trait Verifier {
    type PublicKey;
    type Signature;
    fn new(public_key: Self::PublicKey) -> Self;
    fn verify_message(&self, message: &[u8], signature: &Self::Signature) -> bool;
}
