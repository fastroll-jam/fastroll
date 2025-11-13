//! Ed25519 ZIP-215 compliance tests
//!
//! # Attribution Notice
//!
//! This test suite and harness is copied from
//! [jam-conformance](https://github.com/davxy/jam-conformance) repository.
mod ed25519_consensus {
    use fr_common::{ByteArray, ByteEncodable};
    use fr_crypto::{
        signers::{ed25519::Ed25519Verifier, Verifier},
        types::{Ed25519PubKey, Ed25519Sig},
    };
    use serde::{Deserialize, Serialize};

    const PATH: &str = "jam-conformance/crypto/ed25519/vectors.json";

    #[derive(Serialize, Deserialize)]
    struct TestVector {
        /// Index of the test case
        number: u8,
        /// Description of the test case
        desc: String,
        /// Public key A (32 bytes hex)
        pk: String,
        /// Commitment R (32 bytes hex)
        r: String,
        /// Scalar s (32 bytes hex, always 0 in our case)
        s: String,
        /// Message (hex)
        msg: String,
        /// Whether A encoding is canonical
        pk_canonical: bool,
        /// Whether R encoding is canonical
        r_canonical: bool,
    }

    /// Decoded test vector components
    struct DecodedTestVector {
        vk_array: [u8; 32],
        sig_bytes: [u8; 64],
        message: Vec<u8>,
    }

    /// Load test vectors from JSON file
    fn load_test_vectors() -> Vec<TestVector> {
        let json_data = std::fs::read_to_string(PATH).expect("Failed to read {PATH}");
        serde_json::from_str(json_data.as_str()).expect("Failed to parse {PATH}")
    }

    /// Decode a test vector into byte arrays
    fn decode_test_vector(tv: &TestVector) -> DecodedTestVector {
        let vk_bytes = hex::decode(&tv.pk).expect("Invalid public key hex");
        let r_bytes = hex::decode(&tv.r).expect("Invalid R hex");
        let s_bytes = hex::decode(&tv.s).expect("Invalid s hex");
        let message = hex::decode(&tv.msg).expect("Invalid message hex");

        // Construct the signature: sig = R || s (64 bytes)
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&r_bytes);
        sig_bytes[32..64].copy_from_slice(&s_bytes);

        // Construct the verification key (32 bytes)
        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&vk_bytes);

        DecodedTestVector {
            vk_array,
            sig_bytes,
            message,
        }
    }

    #[test]
    fn test_ed2551_verifier() {
        let test_vectors = load_test_vectors();
        for test_vector in &test_vectors {
            let decoded = decode_test_vector(test_vector);

            let ed25519_verifier = Ed25519Verifier::new(Ed25519PubKey(
                ByteArray::from_slice(&decoded.vk_array).expect("Invalid vk_array"),
            ));

            let sig =
                Ed25519Sig(ByteArray::from_slice(&decoded.sig_bytes).expect("Invalid sig bytes"));

            assert!(ed25519_verifier
                .verify_message(decoded.message.as_slice(), &sig)
                .is_ok());
        }
    }
}
