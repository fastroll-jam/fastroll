#![allow(dead_code)]
use crate::validation::error::ExtrinsicValidationError;
use rjam_codec::JamEncode;
use rjam_common::{Hash32, VALIDATOR_COUNT, X_A};
use rjam_crypto::{hash, verify_signature, Blake2b256};
use rjam_state::StateManager;
use rjam_types::{
    extrinsics::assurances::{AssurancesExtrinsic, AssurancesExtrinsicEntry},
    state::validators::get_validator_ed25519_key_by_index,
};

/// Validates contents of `AssurancesExtrinsic` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Entries in `items` must be ordered by `validator_index`.
///
/// ## Length Limit
/// - The length of `items` must not exceed `VALIDATOR_COUNT`.
///
/// ## Entry Validation
/// - `anchor_parent_hash`
///   - Each entry's `anchor_parent_hash` must match the parent hash of the current block header.
/// - `signature`
///   - Each entry's `signature` must be a valid Ed25519 signature of a message that includes the
///     parent hash and the `assuring_cores_bitvec`, signed by the public key corresponding to the `validator_index`.
/// - `assuring_cores_bitvec`
///   - The `assuring_cores_bitvec` must only have bits set for cores that have pending reports
///     awaiting availability.
pub struct AssurancesExtrinsicValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> AssurancesExtrinsicValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `AssurancesExtrinsic`.
    pub fn validate(
        &self,
        extrinsic: &AssurancesExtrinsic,
        header_parent_hash: Hash32,
    ) -> Result<bool, ExtrinsicValidationError> {
        // Check the length limit
        if extrinsic.len() > VALIDATOR_COUNT {
            return Ok(false);
        }

        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Ok(false);
        }

        // Validate each entry
        let all_valid = extrinsic.items.iter().all(|entry| {
            matches!(self.validate_entry(entry, header_parent_hash), Ok(true)) // TODO: Check if we need error propagation.
        });

        Ok(all_valid)
    }

    /// Validates each `AssurancesExtrinsicEntry`.
    pub fn validate_entry(
        &self,
        entry: &AssurancesExtrinsicEntry,
        header_parent_hash: Hash32,
    ) -> Result<bool, ExtrinsicValidationError> {
        // Check the anchored parent hash
        if entry.anchor_parent_hash != header_parent_hash {
            return Ok(false);
        }

        // Verify the signature
        let mut buf = vec![];
        header_parent_hash.encode_to(&mut buf)?;
        entry.assuring_cores_bitvec.encode_to(&mut buf)?;
        let hash = hash::<Blake2b256>(&buf[..])?;

        let mut message = Vec::with_capacity(X_A.len() + hash.len());
        message.extend_from_slice(X_A);
        message.extend_from_slice(&hash);

        let current_active_set = self.state_manager.get_active_set()?;
        let assurer_public_key =
            get_validator_ed25519_key_by_index(&current_active_set.0, entry.validator_index);

        if !verify_signature(&message, &assurer_public_key, &entry.signature) {
            return Ok(false);
        }

        // Validate the assuring cores bit-vec
        let pending_reports = self.state_manager.get_pending_reports()?;
        for (core_index, bit) in entry.assuring_cores_bitvec.iter().enumerate() {
            // Cannot assure availability of a core without a pending report
            if bit && pending_reports.0[core_index].is_none() {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
