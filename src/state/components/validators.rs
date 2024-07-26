use crate::common::{ValidatorKey, VALIDATOR_COUNT};

use crate::{
    codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput},
    impl_jam_codec_for_newtype,
};

pub(crate) struct StagingValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(StagingValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);

pub(crate) struct ActiveValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(ActiveValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);

pub(crate) struct PastValidatorSet(pub(crate) [ValidatorKey; VALIDATOR_COUNT]);
impl_jam_codec_for_newtype!(PastValidatorSet, [ValidatorKey; VALIDATOR_COUNT]);
