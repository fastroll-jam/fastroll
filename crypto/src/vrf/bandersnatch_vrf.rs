use crate::{
    error::CryptoError,
    types::*,
    vrf::{
        ring::validator_set_to_bandersnatch_ring,
        vrf_core::{
            IetfVrfProverCore, IetfVrfVerifierCore, RingVrfProverCore, RingVrfVerifierCore,
        },
    },
};
use ark_vrf::{
    codec::point_decode, reexports::ark_serialize::CanonicalDeserialize,
    suites::bandersnatch::BandersnatchSha512Ell2, Public, Secret,
};
use fr_common::{ByteArray, ByteEncodable, Hash32, ValidatorIndex};
use tracing::instrument;

pub struct VrfProver {
    core: IetfVrfProverCore,
}

impl VrfProver {
    pub fn from_secret_key(secret_key: &BandersnatchSecretKey) -> Result<Self, CryptoError> {
        let sk = Secret::deserialize_compressed(secret_key.as_slice())?;
        Ok(Self {
            core: IetfVrfProverCore::new(sk),
        })
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            core: IetfVrfProverCore::from_seed(seed),
        }
    }

    pub fn sign_vrf(&self, context: &[u8], message: &[u8]) -> Result<BandersnatchSig, CryptoError> {
        let sig = BandersnatchSig::from_slice(&self.core.ietf_vrf_sign(context, message)?)?;
        Ok(sig)
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
        secret_key: &BandersnatchSecretKey,
    ) -> Result<Self, CryptoError> {
        let ring = validator_set_to_bandersnatch_ring(&validator_set)?;
        let prover = author_index as usize;
        let secret = Secret::deserialize_compressed(secret_key.as_slice())?;

        Ok(Self {
            core: RingVrfProverCore::new(ring, prover, secret),
        })
    }

    pub fn from_seed(
        author_index: ValidatorIndex,
        validator_set: ValidatorKeySet,
        seed: &[u8],
    ) -> Result<Self, CryptoError> {
        let ring = validator_set_to_bandersnatch_ring(&validator_set)?;
        let prover = author_index as usize;
        Ok(Self {
            core: RingVrfProverCore::from_seed(ring, prover, seed),
        })
    }

    pub fn sign_ring_vrf(
        &self,
        context: &[u8],
        message: &[u8],
    ) -> Result<BandersnatchRingVrfSig, CryptoError> {
        Ok(BandersnatchRingVrfSig(Box::new(ByteArray::from_slice(
            &self.core.ring_vrf_sign(context, message)?,
        )?)))
    }
}

#[derive(Clone)]
pub struct RingVrfVerifier {
    core: RingVrfVerifierCore,
}

impl RingVrfVerifier {
    pub fn new(validator_set: &ValidatorKeySet) -> Result<Self, CryptoError> {
        let ring = validator_set_to_bandersnatch_ring(validator_set)?;
        Ok(Self {
            core: RingVrfVerifierCore::new(ring),
        })
    }

    /// Computes Bandersnatch Ring Root from the known validator set (ring)
    pub fn compute_ring_root(&self) -> Result<BandersnatchRingRoot, CryptoError> {
        self.core.compute_ring_root()
    }

    #[instrument(level = "debug", skip_all, name = "verify_ring_vrf")]
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
