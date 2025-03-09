use crate::{
    impl_simple_state_component,
    state_utils::{SimpleStateComponent, StateComponent, StateEntryType, StateKeyConstant},
};
use rjam_codec::{
    impl_jam_codec_for_newtype, JamCodecError, JamDecode, JamDecodeFixed, JamEncode,
    JamEncodeFixed, JamInput, JamOutput,
};
use rjam_common::{ValidatorIndex, VALIDATOR_COUNT};
use std::ops::{Deref, DerefMut};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStatEntry {
    /// `b`: The number of blocks produced by the validator.
    pub blocks_produced_count: u32,
    /// `t`: The number of tickets introduced by the validator.
    pub tickets_count: u32,
    /// `p`: The number of preimages introduced by the validator.
    pub preimages_count: u32,
    /// `d`: The total number of octets across all preimages introduced by the validator.
    pub preimage_data_octets_count: u32,
    /// `g`: The number of reports guaranteed by the validator.
    pub guarantees_count: u32,
    /// `a`: The number of availability assurances made by the validator.
    pub assurances_count: u32,
}

impl JamEncode for ValidatorStatEntry {
    fn size_hint(&self) -> usize {
        4 * 6
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.blocks_produced_count.encode_to_fixed(dest, 4)?;
        self.tickets_count.encode_to_fixed(dest, 4)?;
        self.preimages_count.encode_to_fixed(dest, 4)?;
        self.preimage_data_octets_count.encode_to_fixed(dest, 4)?;
        self.guarantees_count.encode_to_fixed(dest, 4)?;
        self.assurances_count.encode_to_fixed(dest, 4)?;
        Ok(())
    }
}

impl JamDecode for ValidatorStatEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            blocks_produced_count: u32::decode_fixed(input, 4)?,
            tickets_count: u32::decode_fixed(input, 4)?,
            preimages_count: u32::decode_fixed(input, 4)?,
            preimage_data_octets_count: u32::decode_fixed(input, 4)?,
            guarantees_count: u32::decode_fixed(input, 4)?,
            assurances_count: u32::decode_fixed(input, 4)?,
        })
    }
}

/// Holds statistics for all validator activities during a single epoch.
/// Each entry tracks activities such as block production, ticket introduction, and assurances.
///
/// This structure is used both to accumulate statistics for the current epoch
/// and to store completed statistics for the previous epoch.
#[derive(Clone, Debug, PartialEq, Eq, JamEncode, JamDecode)]
pub struct EpochValidatorStats {
    items: Box<[ValidatorStatEntry; VALIDATOR_COUNT]>,
}

impl Deref for EpochValidatorStats {
    type Target = [ValidatorStatEntry];

    fn deref(&self) -> &Self::Target {
        &*self.items
    }
}

impl DerefMut for EpochValidatorStats {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.items
    }
}

impl Default for EpochValidatorStats {
    fn default() -> Self {
        Self {
            items: Box::new([ValidatorStatEntry::default(); VALIDATOR_COUNT]),
        }
    }
}

impl EpochValidatorStats {
    pub fn new(items: Box<[ValidatorStatEntry; VALIDATOR_COUNT]>) -> Self {
        Self { items }
    }

    pub fn validator_stats(&self, validator_index: ValidatorIndex) -> &ValidatorStatEntry {
        &self.items[validator_index as usize]
    }

    pub fn validator_stats_mut(
        &mut self,
        validator_index: ValidatorIndex,
    ) -> &mut ValidatorStatEntry {
        &mut self.items[validator_index as usize]
    }
}

/// The validator activities statistics recorded on-chain, on a per-epoch basis.
///
/// It maintains two records:
/// - The first entry accumulates statistics for the current epoch.
/// - The second entry stores the statistics from the previous epoch.
///
/// Represents `π` of the GP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorStats(pub [EpochValidatorStats; 2]);
impl_jam_codec_for_newtype!(ValidatorStats, [EpochValidatorStats; 2]);
impl_simple_state_component!(ValidatorStats, ValidatorStats);

impl ValidatorStats {
    pub fn current_epoch_stats(&self) -> &EpochValidatorStats {
        &self.0[0]
    }

    pub fn current_epoch_stats_mut(&mut self) -> &mut EpochValidatorStats {
        &mut self.0[0]
    }

    pub fn current_epoch_validator_stats_mut(
        &mut self,
        validator_index: ValidatorIndex,
    ) -> &mut ValidatorStatEntry {
        self.current_epoch_stats_mut()
            .validator_stats_mut(validator_index)
    }

    pub fn previous_epoch_stats(&self) -> &EpochValidatorStats {
        &self.0[1]
    }

    pub fn replace_previous_epoch_stats(&mut self, new_epoch_stats: EpochValidatorStats) {
        self.0[1] = new_epoch_stats
    }

    pub fn clear_current_epoch_stats(&mut self) {
        self.0[0] = EpochValidatorStats::default()
    }
}
