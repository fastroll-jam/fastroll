use crate::validation::error::XtError;
use fr_block::types::extrinsics::preimages::{PreimagesXt, PreimagesXtEntry};
use fr_crypto::{hash, Blake2b256};
use fr_state::manager::StateManager;
use std::{collections::HashSet, sync::Arc};

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
pub struct PreimagesXtValidator {
    state_manager: Arc<StateManager>,
}

impl PreimagesXtValidator {
    pub fn new(state_manager: Arc<StateManager>) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `PreimagesXt`.
    pub async fn validate(&self, extrinsic: &PreimagesXt) -> Result<(), XtError> {
        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(XtError::PreimageLookupsNotSorted);
        }

        // Duplicate validation of the preimage entries
        let mut entries = HashSet::new();
        let no_duplicate = extrinsic.iter().all(|entry| entries.insert(entry));
        if !no_duplicate {
            return Err(XtError::DuplicatePreimageLookup);
        }

        for entry in extrinsic.iter() {
            self.validate_entry(entry).await?;
        }

        Ok(())
    }

    /// Validates each `PreimagesXtEntry`.
    async fn validate_entry(&self, entry: &PreimagesXtEntry) -> Result<(), XtError> {
        let service_id = entry.service_id;
        let preimage_data_len = entry.preimage_data_len();
        let preimage_data_hash = hash::<Blake2b256>(&entry.preimage_data)?;
        let lookups_key = &(preimage_data_hash.clone(), preimage_data_len as u32);

        // Preimage must not be already integrated
        if self
            .state_manager
            .get_account_preimages_entry(service_id, &preimage_data_hash)
            .await?
            .is_some()
        {
            return Err(XtError::PreimageAlreadyIntegrated(service_id));
        }

        // Preimage must be solicited
        match self
            .state_manager
            .get_account_lookups_entry(service_id, lookups_key)
            .await?
        {
            Some(entry) if entry.value.is_empty() => Ok(()),
            _ => Err(XtError::PreimageNotSolicited(service_id)),
        }
    }
}
