/// Used for Ed25519, BLS keys.
pub trait Signer {
    type SecretKey;
    type Signature;
    fn from_secret_key(key: Self::SecretKey) -> Self;
    fn sign_message(&self, message: &[u8]) -> Self::Signature;
}

/// Used for Ed25519, BLS keys.
pub trait Verifier {
    type PublicKey;
    type Signature;
    fn verify_message(
        &self,
        message: &[u8],
        pub_key: &Self::PublicKey,
        signature: &Self::Signature,
    ) -> bool;
}
