use crate::{
    bandersnatch::vrf_core::{
        IetfVrfProverCore, IetfVrfSignature, IetfVrfVerifierCore, RingVrfProverCore,
        RingVrfSignature, RingVrfVerifierCore,
    },
    validator_set_to_bandersnatch_ring, CryptoError,
};
use ark_vrf::{
    codec::point_decode, reexports::ark_serialize::CanonicalDeserialize,
    suites::bandersnatch::BandersnatchSha512Ell2, Public, Secret,
};
use rjam_common::{
    BandersnatchPubKey, BandersnatchRingVrfSig, BandersnatchSecretKey, BandersnatchSig, ByteArray,
    Hash32, ValidatorIndex, ValidatorKeySet,
};

pub struct VrfProver {
    core: IetfVrfProverCore,
}

impl VrfProver {
    pub fn from_secret_key(secret_key: BandersnatchSecretKey) -> Self {
        Self {
            core: IetfVrfProverCore::new(
                Secret::deserialize_compressed(secret_key.as_slice()).unwrap(),
            ),
        }
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            core: IetfVrfProverCore::from_seed(seed),
        }
    }

    pub fn sign_vrf(&self, context: &[u8], message: &[u8]) -> BandersnatchSig {
        let sig = self.core.ietf_vrf_sign(context, message);
        BandersnatchSig::try_from_vec(sig).unwrap()
    }
}

pub struct VrfVerifier;
impl VrfVerifier {
    pub fn verify_vrf(
        context: &[u8],
        message: &[u8],
        signature: &BandersnatchSig,
        public_key: &BandersnatchPubKey,
    ) -> Result<Hash32, CryptoError> {
        IetfVrfVerifierCore::ietf_vrf_verify(
            context,
            message,
            signature.as_slice(),
            Public::from(
                point_decode::<BandersnatchSha512Ell2>(public_key.as_slice())
                    .map_err(|_| CryptoError::BandersnatchDecodeError)?,
            ),
        )
        .map(Hash32::new)
    }
}

pub struct RingVrfProver {
    core: RingVrfProverCore,
}

impl RingVrfProver {
    pub fn from_secret_key(
        author_index: ValidatorIndex,
        validator_set: ValidatorKeySet,
        secret_key: BandersnatchSecretKey,
    ) -> Self {
        Self {
            core: RingVrfProverCore::new(
                validator_set_to_bandersnatch_ring(&validator_set).unwrap(),
                author_index as usize,
                Secret::deserialize_compressed(secret_key.as_slice()).unwrap(),
            ),
        }
    }

    pub fn from_seed(
        author_index: ValidatorIndex,
        validator_set: ValidatorKeySet,
        seed: &[u8],
    ) -> Self {
        Self {
            core: RingVrfProverCore::from_seed(
                validator_set_to_bandersnatch_ring(&validator_set).unwrap(),
                author_index as usize,
                seed,
            ),
        }
    }

    pub fn sign_ring_vrf(&self, context: &[u8], message: &[u8]) -> BandersnatchRingVrfSig {
        let sig = self.core.ring_vrf_sign(context, message);
        Box::new(ByteArray::try_from_vec(sig).unwrap())
    }
}

pub struct RingVrfVerifier {
    core: RingVrfVerifierCore,
}

impl RingVrfVerifier {
    pub fn new(validator_set: ValidatorKeySet) -> Self {
        Self {
            core: RingVrfVerifierCore::new(
                validator_set_to_bandersnatch_ring(&validator_set).unwrap(),
            ),
        }
    }

    pub fn verify_ring_vrf(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &BandersnatchRingVrfSig,
    ) -> Result<Hash32, CryptoError> {
        self.core
            .ring_vrf_verify(context, message, signature.as_slice())
            .map(Hash32::new)
    }
}

/// `Y` hash output function for a VRF signature
pub fn entropy_hash_ietf_vrf(signature_bytes: &BandersnatchSig) -> Hash32 {
    Hash32::new(
        IetfVrfSignature::deserialize_compressed(&signature_bytes[..])
            .unwrap()
            .output_hash(),
    )
}

/// `Y` hash output function for an anonymous RingVRF signature
pub fn entropy_hash_ring_vrf(signature_bytes: &BandersnatchRingVrfSig) -> Hash32 {
    Hash32::new(
        RingVrfSignature::deserialize_compressed(&signature_bytes[..])
            .unwrap()
            .output_hash(),
    )
}
