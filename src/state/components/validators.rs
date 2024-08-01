use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::VALIDATOR_COUNT,
    impl_jam_codec_for_newtype,
};

pub type ValidatorSet = [ValidatorKey; VALIDATOR_COUNT];

#[derive(Copy, Clone)]
pub struct ValidatorKey {
    pub bandersnatch_key: [u8; 32],
    pub ed25519_key: [u8; 32],
    pub bls_key: [u8; 144],
    pub metadata: [u8; 128],
}

impl ValidatorKey {
    pub fn to_bytes(&self) -> [u8; 336] {
        let mut result = [0u8; 336];

        result[0..32].copy_from_slice(&self.bandersnatch_key);
        result[32..64].copy_from_slice(&self.ed25519_key);
        result[64..208].copy_from_slice(&self.bls_key);
        result[208..336].copy_from_slice(&self.metadata);

        result
    }
}

impl Default for ValidatorKey {
    fn default() -> Self {
        ValidatorKey {
            bandersnatch_key: [0u8; 32],
            ed25519_key: [0u8; 32],
            bls_key: [0u8; 144],
            metadata: [0u8; 128],
        }
    }
}

impl JamEncode for ValidatorKey {
    fn size_hint(&self) -> usize {
        self.bandersnatch_key.size_hint()
            + self.ed25519_key.size_hint()
            + self.bls_key.size_hint()
            + self.metadata.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.bandersnatch_key.encode_to(dest)?;
        self.ed25519_key.encode_to(dest)?;
        self.bls_key.encode_to(dest)?;
        self.metadata.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for ValidatorKey {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            bandersnatch_key: JamDecode::decode(input)?,
            ed25519_key: JamDecode::decode(input)?,
            bls_key: JamDecode::decode(input)?,
            metadata: JamDecode::decode(input)?,
        })
    }
}

pub struct StagingValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(StagingValidatorSet, ValidatorSet);

pub struct ActiveValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(ActiveValidatorSet, ValidatorSet);

pub struct PastValidatorSet(pub ValidatorSet);
impl_jam_codec_for_newtype!(PastValidatorSet, ValidatorSet);
