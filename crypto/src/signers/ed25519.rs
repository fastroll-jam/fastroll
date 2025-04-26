use crate::types::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rjam_common::ByteEncodable;

pub struct Ed25519Signer {
    secret_key: Ed25519SecretKey,
}

impl crate::signers::Signer for Ed25519Signer {
    type SecretKey = Ed25519SecretKey;
    type Signature = Ed25519Sig;

    fn new(secret_key: Self::SecretKey) -> Self {
        Self { secret_key }
    }

    fn sign_message(&self, message: &[u8]) -> Self::Signature {
        let signing_key = SigningKey::from_bytes(&self.secret_key.0);
        let signature = signing_key.sign(message);
        Ed25519Sig::from_slice(signature.to_bytes().as_slice()).unwrap()
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

    fn verify_message(&self, message: &[u8], signature: &Self::Signature) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.public_key.0) {
            Ok(key) => key,
            Err(_) => return false, // Invalid public key
        };
        let signature = Signature::from_bytes(&signature.0);
        verifying_key.verify(message, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::{Signer, Verifier};
    use rand::rngs::OsRng;
    use rjam_common::ByteEncodable;

    // Helper function to create a message
    fn create_message() -> Vec<u8> {
        b"Some message".to_vec()
    }

    // Helper function to generate a random signer
    fn generate_random_signer() -> SigningKey {
        let mut rng = OsRng;
        SigningKey::generate(&mut rng)
    }

    // Helper function to generate a random secret key and public key
    fn setup() -> (Ed25519Signer, Ed25519Verifier, Vec<u8>) {
        let signing_key = generate_random_signer();
        let secret_key = Ed25519SecretKey::from_slice(signing_key.to_bytes().as_slice()).unwrap();
        let public_key =
            Ed25519PubKey::from_slice(signing_key.verifying_key().to_bytes().as_slice()).unwrap();

        let signer = Ed25519Signer::new(secret_key);
        let verifier = Ed25519Verifier::new(public_key);

        let message = create_message();
        (signer, verifier, message)
    }

    #[test]
    fn test_sign_and_verify() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message);
        assert!(verifier.verify_message(&message, &signature));
    }

    #[test]
    fn test_sign_and_verify_different_message() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message);
        let mut different_message = message.clone();
        different_message.push(0x01);
        assert!(!verifier.verify_message(&different_message, &signature));
    }

    #[test]
    fn test_invalid_signature() {
        let (signer, verifier, message) = setup();
        let signature = signer.sign_message(&message);
        let mut invalid_signature = signature.0.to_vec();
        invalid_signature[0] ^= 0x01;
        let invalid_signature = Ed25519Sig::from_slice(
            Signature::from_slice(&invalid_signature)
                .unwrap()
                .to_bytes()
                .as_slice(),
        )
        .unwrap();
        assert!(!verifier.verify_message(&message, &invalid_signature));
    }

    #[test]
    fn test_invalid_public_key() {
        let (signer, _verifier, message) = setup();
        let signature = signer.sign_message(&message);
        let invalid_public_key = Ed25519PubKey::from_slice(
            generate_random_signer()
                .verifying_key()
                .to_bytes()
                .as_slice(),
        )
        .unwrap();
        let invalid_verifier = Ed25519Verifier::new(invalid_public_key);
        assert!(!invalid_verifier.verify_message(&message, &signature));
    }
}
