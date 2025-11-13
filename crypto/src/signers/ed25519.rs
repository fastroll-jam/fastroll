use crate::{error::CryptoError, types::*};
use ed25519_consensus::{Signature, SigningKey, VerificationKey};
use fr_common::ByteEncodable;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Signer {
    secret_key: Ed25519SecretKey,
}

impl crate::signers::Signer for Ed25519Signer {
    type SecretKey = Ed25519SecretKey;
    type Signature = Ed25519Sig;

    fn new(secret_key: Self::SecretKey) -> Self {
        Self { secret_key }
    }

    fn sign_message(&self, message: &[u8]) -> Result<Self::Signature, CryptoError> {
        let signing_key = SigningKey::try_from(self.secret_key.as_slice())?;
        let signature = signing_key.sign(message);
        let sig = Ed25519Sig::from_slice(signature.to_bytes().as_slice())?;
        Ok(sig)
    }
}

pub struct Ed25519Verifier {
    public_key: Ed25519PubKey,
}

impl crate::signers::Verifier for Ed25519Verifier {
    type PublicKey = Ed25519PubKey;
    type Signature = Ed25519Sig;

    fn new(public_key: Self::PublicKey) -> Self {
        Self { public_key }
    }

    fn verify_message(
        &self,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), CryptoError> {
        let verification_key = VerificationKey::try_from(self.public_key.as_slice())?;
        let signature = Signature::try_from(signature.as_slice())?;
        verification_key.verify(&signature, message)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::{Signer, Verifier};
    use fr_common::ByteEncodable;
    use rand::rngs::OsRng;

    // Helper function to create a message
    fn create_message() -> Vec<u8> {
        b"Some message".to_vec()
    }

    // Helper function to generate a random signer
    fn generate_random_signer() -> SigningKey {
        SigningKey::new(OsRng)
    }

    // Helper function to generate a random secret key and public key
    fn setup() -> (Ed25519Signer, Ed25519Verifier, Vec<u8>) {
        let signing_key = generate_random_signer();
        let secret_key = Ed25519SecretKey::from_slice(signing_key.to_bytes().as_slice()).unwrap();
        let public_key =
            Ed25519PubKey::from_slice(signing_key.verification_key().to_bytes().as_slice())
                .unwrap();

        let signer = Ed25519Signer::new(secret_key);
        let verifier = Ed25519Verifier::new(public_key);

        let message = create_message();
        (signer, verifier, message)
    }

    #[test]
    fn test_sign_and_verify() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message).expect("Signing failed");
        assert!(verifier.verify_message(&message, &signature).is_ok());
    }

    #[test]
    fn test_sign_and_verify_different_message() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message).expect("Signing failed");
        let mut different_message = message.clone();
        different_message.push(0x01);
        assert!(verifier
            .verify_message(&different_message, &signature)
            .is_err());
    }

    #[test]
    fn test_invalid_signature() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message).expect("Signing failed");
        let mut invalid_signature = signature.0.to_vec();
        invalid_signature[0] ^= 0x01;
        let invalid_signature = Ed25519Sig::from_slice(
            Signature::try_from(invalid_signature.as_slice())
                .unwrap()
                .to_bytes()
                .as_slice(),
        )
        .unwrap();
        assert!(verifier
            .verify_message(&message, &invalid_signature)
            .is_err());
    }

    #[test]
    fn test_invalid_public_key() {
        let (signer, _verifier, message) = setup();
        let signature = signer.sign_message(&message).expect("Signing failed");
        let invalid_public_key = Ed25519PubKey::from_slice(
            generate_random_signer()
                .verification_key()
                .to_bytes()
                .as_slice(),
        )
        .unwrap();
        let invalid_verifier = Ed25519Verifier::new(invalid_public_key);
        assert!(invalid_verifier
            .verify_message(&message, &signature)
            .is_err());
    }
}
