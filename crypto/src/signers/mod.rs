use crate::error::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod bls;
pub mod ed25519;

/// Used for Ed25519, BLS keys.
pub trait Signer: Zeroize + ZeroizeOnDrop {
    type SecretKey;
    type Signature;
    fn new(key: Self::SecretKey) -> Self;
    fn sign_message(&self, message: &[u8]) -> Result<Self::Signature, CryptoError>;
}

/// Used for Ed25519, BLS keys.
pub trait Verifier {
    type PublicKey;
    type Signature;
    fn new(public_key: Self::PublicKey) -> Self;
    fn verify_message(
        &self,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), CryptoError>;
}
