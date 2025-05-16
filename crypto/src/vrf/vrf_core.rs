//! # Attribution Notice
//!
//! This module is based on the [bandersnatch-vrfs-spec](https://github.com/davxy/bandersnatch-vrfs-spec)
//! repository, with modifications as needed.
use crate::error::CryptoError;
use ark_vrf::{
    reexports::ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
    suites::bandersnatch,
};
use bandersnatch::{
    BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof, RingProofParams, Secret,
};
use fr_common::VALIDATOR_COUNT;

pub const RING_SIZE: usize = VALIDATOR_COUNT;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// Additional impl
impl IetfVrfSignature {
    pub(crate) fn output_hash(&self) -> [u8; 32] {
        self.output.hash()[..32].try_into().unwrap()
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

// Additional impl
impl RingVrfSignature {
    pub(crate) fn output_hash(&self) -> [u8; 32] {
        self.output.hash()[..32].try_into().unwrap()
    }
}

fn ring_proof_params() -> &'static RingProofParams {
    use std::sync::OnceLock;
    static PARAMS: OnceLock<RingProofParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        use bandersnatch::PcsParams;
        use std::{fs::File, io::Read};
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let filename = format!("{manifest_dir}/../crypto/data/zcash-srs-2-11-uncompressed.bin",);
        let mut file = File::open(filename).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
        RingProofParams::from_pcs_params(RING_SIZE, pcs_params).unwrap()
    })
}

fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    Input::new(vrf_input_data).unwrap()
}

/// IETF VRF prover actor.
/// TODO: Zeroize
pub(crate) struct IetfVrfProverCore {
    secret: Secret,
}

impl IetfVrfProverCore {
    pub(crate) fn new(secret: Secret) -> Self {
        Self { secret }
    }

    pub(crate) fn from_seed(seed: &[u8]) -> Self {
        Self {
            secret: Secret::from_seed(seed),
        }
    }

    /// Non-Anonymous VRF signature.
    ///
    /// Used for ticket claiming during block production.
    /// Not used with Safrole test vectors.
    ///
    /// Returns 96-octet sequence.
    pub(crate) fn ietf_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_vrf::ietf::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);
        let proof = self.secret.prove(input, output, aux_data);

        let signature = IetfVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

/// Ring VRF prover actor.
/// TODO: Zeroize
pub(crate) struct RingVrfProverCore {
    prover_idx: usize,
    secret: Secret,
    ring: Vec<Public>,
}

impl RingVrfProverCore {
    pub(crate) fn new(ring: Vec<Public>, prover_idx: usize, secret: Secret) -> Self {
        Self {
            prover_idx,
            secret,
            ring,
        }
    }

    pub(crate) fn from_seed(ring: Vec<Public>, prover_idx: usize, seed: &[u8]) -> Self {
        Self {
            prover_idx,
            secret: Secret::from_seed(seed),
            ring,
        }
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    ///
    /// Returns 784-octet sequence.
    pub(crate) fn ring_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_vrf::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let params = ring_proof_params();
        let prover_key = params.prover_key(&pts);
        let prover = params.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

/// IETF VRF verifier actor (Ring and its commitment).
pub(crate) struct IetfVrfVerifierCore;
impl IetfVrfVerifierCore {
    /// Non-Anonymous VRF signature verification.
    ///
    /// Used for ticket claim verification during block import.
    /// Not used with Safrole test vectors.
    ///
    /// On success returns the VRF output hash.
    pub(crate) fn ietf_vrf_verify(
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
        public: Public,
    ) -> Result<[u8; 32], CryptoError> {
        use ark_vrf::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        if public
            .verify(input, output, aux_data, &signature.proof)
            .is_err()
        {
            tracing::error!("Ring signature verification failure");
            return Err(CryptoError::VrfVerificationFailed);
        }
        tracing::debug!("Ietf signature verified");

        // `Y` hashed value; this is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        tracing::debug!("vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}

pub(crate) type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

/// Ring VRF verifier actor (Ring and its commitment).
pub(crate) struct RingVrfVerifierCore {
    pub(crate) commitment: RingCommitment,
    #[allow(dead_code)]
    ring: Vec<Public>,
}

impl RingVrfVerifierCore {
    pub(crate) fn new(ring: Vec<Public>) -> Self {
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let verifier_key = ring_proof_params().verifier_key(&pts);
        let commitment = verifier_key.commitment(); // The Ring Root
        Self { ring, commitment }
    }

    /// Anonymous VRF signature verification.
    ///
    /// Used for tickets verification.
    ///
    /// On success returns the VRF output hash.
    pub(crate) fn ring_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        use ark_vrf::ring::Verifier as _;

        let signature = RingVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output; // extracted from the signature

        let params = ring_proof_params();

        let verifier_key = params.verifier_key_from_commitment(self.commitment.clone());
        let verifier = params.verifier(verifier_key);
        if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
            tracing::error!("Ring signature verification failure");
            return Err(CryptoError::VrfVerificationFailed);
        }
        tracing::debug!("Ring signature verified");

        // `Y` hashed value; the actual value used as ticket-id/score
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        tracing::debug!("vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}
