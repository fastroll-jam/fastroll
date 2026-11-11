use crate::utils::shuffle::{shuffle_with_hash, ShuffleError};
use fr_common::{CoreIndex, Hash32, EPOCH_LENGTH, GUARANTOR_ROTATION_PERIOD, MAX_VALIDATOR_COUNT};
use fr_crypto::types::ValidatorKeySet;
use fr_limited_vec::LimitedVec;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{Timeslot, ValidatorSet},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GuarantorAssignmentError {
    #[error("Invalid validators length")]
    InvalidValidatorsLength,
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("ShuffleError: {0}")]
    ShuffleError(#[from] ShuffleError),
}

pub type CoreIndices = LimitedVec<CoreIndex, MAX_VALIDATOR_COUNT>;

pub struct GuarantorAssignment {
    /// `c`: Indices of cores allocated to validators, indexed by validator indices.
    pub core_indices: CoreIndices,
    /// `k`: Validator keys indexed by validator indices.
    pub validator_keys: ValidatorKeySet,
}

impl GuarantorAssignment {
    /// Represents rotation function `R` from the GP.
    /// Shifts each core index by `shift` modulo the `|c|/3` cores that the validators cover.
    fn rotate_validator_indices(indices: Vec<u16>, shift: u16) -> Vec<u16> {
        let covered_core_count = (indices.len() / 3) as u16;
        if covered_core_count == 0 {
            return indices;
        }
        indices
            .into_iter()
            .map(|index| (index + shift) % covered_core_count)
            .collect()
    }

    /// Represents permute function `P` of the GP for a validator set of `validator_count` validators.
    /// Assigns the core `⌊i/3⌋` to validator `i` before the shuffle, so each core gets three validators.
    fn permute_validator_indices(
        validator_count: usize,
        entropy: &Hash32,
        timeslot: Timeslot,
    ) -> Result<Vec<u16>, GuarantorAssignmentError> {
        let indices: Vec<u16> = (0..validator_count).map(|i| (i / 3) as u16).collect();
        let shuffled_indices = shuffle_with_hash(indices, entropy)?;
        let rotation_shift =
            (timeslot.slot() % EPOCH_LENGTH as u32) / GUARANTOR_ROTATION_PERIOD as u32;
        Ok(Self::rotate_validator_indices(
            shuffled_indices,
            rotation_shift as u16,
        ))
    }

    /// The output represents **`M`** of the GP.
    pub async fn current_guarantor_assignments(
        state_manager: &StateManager,
    ) -> Result<Self, GuarantorAssignmentError> {
        let current_timeslot = state_manager.get_timeslot().await?;
        let epoch_entropy = state_manager.get_epoch_entropy().await?;
        let entropy_2 = epoch_entropy.second_history();
        let mut active_set = state_manager.get_active_set().await?;
        let punish_set = state_manager.get_disputes().await?.punish_set;
        active_set.nullify_punished_validators(&punish_set);

        Ok(Self {
            core_indices: CoreIndices::try_from(Self::permute_validator_indices(
                active_set.len(),
                entropy_2,
                current_timeslot,
            )?)
            .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
            validator_keys: active_set.0,
        })
    }

    /// The output represents **`M*`** of the GP.
    pub async fn previous_guarantor_assignments(
        state_manager: &StateManager,
    ) -> Result<Self, GuarantorAssignmentError> {
        let current_timeslot = state_manager.get_timeslot().await?;
        let punish_set = state_manager.get_disputes().await?.punish_set;
        let entropy = state_manager.get_epoch_entropy().await?;
        let previous_rotation_timeslot = Timeslot::new(
            current_timeslot
                .slot()
                .saturating_sub(GUARANTOR_ROTATION_PERIOD as u32),
        );

        let within_same_epoch = previous_rotation_timeslot.epoch() == current_timeslot.epoch();
        let (entropy, mut validator_set) = if within_same_epoch {
            (
                entropy.second_history(),
                state_manager.get_active_set().await?.0,
            )
        } else {
            (
                entropy.third_history(),
                state_manager.get_past_set().await?.0,
            )
        };
        validator_set.nullify_punished_validators(&punish_set);

        Ok(Self {
            core_indices: CoreIndices::try_from(Self::permute_validator_indices(
                validator_set.len(),
                entropy,
                previous_rotation_timeslot,
            )?)
            .map_err(|_| GuarantorAssignmentError::InvalidValidatorsLength)?,
            validator_keys: validator_set,
        })
    }
}
