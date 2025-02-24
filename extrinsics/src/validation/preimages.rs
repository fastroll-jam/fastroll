use crate::validation::error::{XtValidationError, XtValidationError::*};
use rjam_crypto::{hash, Blake2b256};
use rjam_state::StateManager;
use rjam_types::extrinsics::preimages::{PreimagesXt, PreimagesXtEntry};
use std::collections::HashSet;

/// Validate contents of `PreimagesXt` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Extrinsic entries must be ordered by `service_id`.
///
/// ## Length Limit
/// - No length limit applies.
///
/// ## Entry Validation
/// - No duplicate entries are allowed within the extrinsic.
/// - Each entry must not be already integrated to the corresponding service account's state.
///   Thus, the solicited data must not exist in the service account's preimage lookup tables.
pub struct PreimagesXtValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> PreimagesXtValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `PreimagesXt`.
    pub async fn validate(&self, extrinsic: &PreimagesXt) -> Result<(), XtValidationError> {
        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(PreimageLookupsNotSorted);
        }

        // Duplicate validation of the preimage entries
        let mut entries = HashSet::new();
        let no_duplicate = extrinsic.iter().all(|entry| entries.insert(entry));
        if !no_duplicate {
            return Err(DuplicatePreimageLookup);
        }

        for entry in extrinsic.iter() {
            self.validate_entry(entry).await?;
        }

        Ok(())
    }

    /// Validates each `PreimagesXtEntry`.
    async fn validate_entry(&self, entry: &PreimagesXtEntry) -> Result<(), XtValidationError> {
        let service_id = entry.service_id;
        let preimage_data_len = entry.preimage_data_len();
        let preimage_data_hash = hash::<Blake2b256>(&entry.preimage_data)?;
        let lookups_key = &(preimage_data_hash, preimage_data_len as u32);

        // Preimage must not be already integrated
        if self
            .state_manager
            .get_account_preimages_entry(service_id, &preimage_data_hash)
            .await?
            .is_some()
        {
            return Err(PreimageAlreadyIntegrated(service_id));
        }

        // Preimage must be solicited
        match self
            .state_manager
            .get_account_lookups_entry(service_id, lookups_key)
            .await?
        {
            Some(entry) => {
                if !entry.value.is_empty() {
                    return Err(PreimageNotSolicited(service_id));
                }
            }
            None => return Err(PreimageNotSolicited(service_id)),
        }

        Ok(())
    }
}
