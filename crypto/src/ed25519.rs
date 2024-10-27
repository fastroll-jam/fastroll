use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rjam_common::{Ed25519PubKey, Ed25519SecretKey, Ed25519Signature};

// TODO: Better key type handling.

pub fn generate_random_signer() -> SigningKey {
    let mut rng = OsRng;
    SigningKey::generate(&mut rng)
}

pub fn sign_message(message: &[u8], secret_key: &Ed25519SecretKey) -> Ed25519Signature {
    let signing_key = SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

pub fn verify_signature(
    message: &[u8],
    public_key: &Ed25519PubKey,
    signature: &Ed25519Signature,
) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false, // Invalid public key
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rjam_common::Octets;

    // Helper function to create a message
    fn create_message() -> Octets {
        b"Some message".to_vec()
    }

    // Helper function to generate a random secret key and public key
    fn setup() -> (Ed25519SecretKey, Ed25519PubKey, Vec<u8>) {
        let signing_key = generate_random_signer();
        let secret_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();
        let message = create_message();
        (secret_key, public_key, message)
    }

    #[test]
    fn test_sign_and_verify() {
        let (secret_key, public_key, message) = setup();
        let signature = sign_message(&message, &secret_key);
        assert!(verify_signature(&message, &public_key, &signature));
    }

    #[test]
    fn test_sign_and_verify_different_message() {
        let (secret_key, public_key, message) = setup();
        let signature = sign_message(&message, &secret_key);
        let mut different_message = message.clone();
        different_message.push(0x01);
        assert!(!verify_signature(
            &different_message,
            &public_key,
            &signature
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let (secret_key, public_key, message) = setup();
        let signature = sign_message(&message, &secret_key);
        let mut invalid_signature = signature.to_vec();
        invalid_signature[0] ^= 0x01;
        let invalid_signature = Signature::from_slice(&invalid_signature).unwrap();
        assert!(!verify_signature(
            &message,
            &public_key,
            &invalid_signature.to_bytes()
        ));
    }

    #[test]
    fn test_invalid_public_key() {
        let (secret_key, _public_key, message) = setup();
        let signature = sign_message(&message, &secret_key);
        let invalid_public_key = generate_random_signer().verifying_key().to_bytes();
        assert!(!verify_signature(&message, &invalid_public_key, &signature));
    }
}
