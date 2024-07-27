use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    common::VALIDATOR_COUNT,
    impl_jam_codec_for_newtype,
};

#[derive(Copy, Clone)]
pub(crate) struct ValidatorKey {
    bandersnatch_key: [u8; 32],
    ed25519_key: [u8; 32],
    bls_key: [u8; 144],
    metadata: [u8; 128],
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

pub(crate) struct StagingValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(StagingValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);

pub(crate) struct ActiveValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(ActiveValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);

pub(crate) struct PastValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(PastValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);
