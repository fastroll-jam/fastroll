use crate::validation::error::{ExtrinsicValidationError, ExtrinsicValidationError::*};
use rjam_crypto::{hash, Blake2b256};
use rjam_state::StateManager;
use rjam_types::extrinsics::preimages::{PreimageLookupsExtrinsic, PreimageLookupsExtrinsicEntry};
use std::collections::HashSet;

/// Validate contents of `PreimagesExtrinsic` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Extrinsic entries must be ordered by `service_index`.
///
/// ## Length Limit
/// - No length limit applies.
///
/// ## Entry Validation
/// - No duplicate entries are allowed within the extrinsic.
/// - Each entry must not be already integrated to the corresponding service account's state.
///   Thus, the solicited data must not exist in the service account's preimage lookup tables.
pub struct PreimagesExtrinsicValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> PreimagesExtrinsicValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `PreimageLookupsExtrinsic`.
    pub fn validate(
        &self,
        extrinsic: &PreimageLookupsExtrinsic,
    ) -> Result<(), ExtrinsicValidationError> {
        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(PreimageLookupsNotOrdered);
        }

        // Duplicate validation of the preimage entries
        let mut entries = HashSet::new();
        let no_duplicate = extrinsic.iter().all(|entry| entries.insert(entry));
        if !no_duplicate {
            return Err(DuplicatePreimageLookups);
        }

        for entry in extrinsic.iter() {
            self.validate_entry(entry)?;
        }

        Ok(())
    }

    /// Validates each `PreimageLookupsExtrinsicEntry`.
    pub fn validate_entry(
        &self,
        entry: &PreimageLookupsExtrinsicEntry,
    ) -> Result<(), ExtrinsicValidationError> {
        let service_index = entry.service_index;
        let preimage_data_len = entry.preimage_data_len();
        let preimage_data_hash = hash::<Blake2b256>(&entry.preimage_data)?;
        let lookups_key = (&preimage_data_hash, preimage_data_len as u32);

        if self
            .state_manager
            .get_account_preimages_entry(service_index, &preimage_data_hash)?
            .is_some()
        {
            return Err(PreimageAlreadyIntegrated);
        }

        if self
            .state_manager
            .get_account_lookups_entry(service_index, lookups_key)?
            .is_some()
        {
            return Err(PreimageAlreadyIntegrated);
        }

        Ok(())
    }
}
