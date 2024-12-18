use crate::utils::shuffle::shuffle_with_hash;
use rjam_common::{
    CoreIndex, Ed25519PubKey, Hash32, CORE_COUNT, EPOCH_LENGTH, GUARANTOR_ROTATION_PERIOD,
    VALIDATOR_COUNT,
};
use rjam_state::{StateManager, StateManagerError};
use rjam_types::state::{timeslot::Timeslot, validators::ValidatorSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuarantorAssignmentError {
    #[error("Invalid validators length")]
    InvalidValidatorsLength,
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
}

#[allow(dead_code)]
pub struct GuarantorAssignment {
    core_indices: Box<[CoreIndex; VALIDATOR_COUNT]>,
    validator_keys: Box<[Ed25519PubKey; VALIDATOR_COUNT]>,
}

impl GuarantorAssignment {
    /// Represents rotation function `R` from the GP.
    fn rotate_validator_indices(indices: Vec<u16>, shift: u16) -> Vec<u16> {
        indices
            .into_iter()
            .map(|index| (index + shift) % CORE_COUNT as u16)
            .collect()
    }

    /// Represents permute function `P` of the GP.
    fn permute_validator_indices(entropy: Hash32, timeslot: Timeslot) -> Vec<u16> {
        let indices: Vec<u16> = (0..VALIDATOR_COUNT)
            .map(|i| (CORE_COUNT * i / VALIDATOR_COUNT) as u16)
            .collect();
        let shuffled_indices = shuffle_with_hash(indices, &entropy);
        let rotation_shift =
            (timeslot.slot() % EPOCH_LENGTH as u32) / GUARANTOR_ROTATION_PERIOD as u32;
        Self::rotate_validator_indices(shuffled_indices, rotation_shift as u16)
    }

    /// Represents `G` of the GP.
    pub fn current_guarantor_assignments(
        state_manager: &StateManager,
    ) -> Result<Self, GuarantorAssignmentError> {
        let current_timeslot = state_manager.get_timeslot()?;
        let entropy_2 = state_manager.get_entropy_accumulator()?.second_history();
        let mut active_set = state_manager.get_active_set()?;
        let punish_set = state_manager.get_disputes()?.punish_set;
        active_set.nullify_punished_validators(&punish_set);

        Ok(Self {
            core_indices: Self::permute_validator_indices(entropy_2, current_timeslot)
                .try_into()
                .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
            validator_keys: active_set
                .ed25519_keys()
                .try_into()
                .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
        })
    }

    /// Represents `G*` of the GP.
    pub fn previous_guarantor_assignments(
        state_manager: &StateManager,
    ) -> Result<Self, GuarantorAssignmentError> {
        let current_timeslot = state_manager.get_timeslot()?;
        let punish_set = state_manager.get_disputes()?.punish_set;
        let entropy = state_manager.get_entropy_accumulator()?;
        let previous_timeslot_value = current_timeslot.slot() - GUARANTOR_ROTATION_PERIOD as u32;
        let within_same_epoch = previous_timeslot_value / EPOCH_LENGTH as u32
            == current_timeslot.slot() / EPOCH_LENGTH as u32;

        let (entropy, ref mut validator_set) = if within_same_epoch {
            (entropy.second_history(), state_manager.get_active_set()?.0)
        } else {
            (entropy.third_history(), state_manager.get_past_set()?.0)
        };
        validator_set.nullify_punished_validators(&punish_set);

        Ok(Self {
            core_indices: Self::permute_validator_indices(
                entropy,
                Timeslot::new(previous_timeslot_value),
            )
            .try_into()
            .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
            validator_keys: validator_set
                .ed25519_keys()
                .try_into()
                .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
        })
    }
}
