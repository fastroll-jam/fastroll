use crate::validation::error::XtError;
use rjam_block::types::extrinsics::assurances::{AssurancesXt, AssurancesXtEntry};
use rjam_codec::{JamEncode, JamEncodeFixed};
use rjam_common::{CoreIndex, Hash32, CORE_COUNT, VALIDATOR_COUNT, X_A};
use rjam_crypto::{
    hash,
    signers::{ed25519::Ed25519Verifier, Verifier},
    Blake2b256,
};
use rjam_state::manager::StateManager;
use std::collections::HashSet;

/// Validates contents of `AssurancesXt` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Extrinsic entries must be ordered by `validator_index`.
///
/// ## Length Limit
/// - The length must not exceed `VALIDATOR_COUNT`.
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
pub struct AssurancesXtValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> AssurancesXtValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `AssurancesXt`.
    pub async fn validate(
        &self,
        extrinsic: &AssurancesXt,
        header_parent_hash: &Hash32,
    ) -> Result<(), XtError> {
        // Check the length limit
        if extrinsic.len() > VALIDATOR_COUNT {
            return Err(XtError::AssurancesEntryLimitExceeded(
                extrinsic.len(),
                VALIDATOR_COUNT,
            ));
        }

        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(XtError::AssurancesNotSorted);
        }

        // Duplicate validation of assurers' validator indices
        let mut assurers = HashSet::new();
        let no_duplicate_assurer = extrinsic
            .iter()
            .all(|entry| assurers.insert(entry.validator_index));
        if !no_duplicate_assurer {
            return Err(XtError::DuplicateAssurer);
        }

        // Validate each entry
        for entry in extrinsic.iter() {
            self.validate_entry(entry, header_parent_hash).await?;
        }

        Ok(())
    }

    /// Validates each `AssurancesXtEntry`.
    async fn validate_entry(
        &self,
        entry: &AssurancesXtEntry,
        header_parent_hash: &Hash32,
    ) -> Result<(), XtError> {
        // Check the anchored parent hash
        if &entry.anchor_parent_hash != header_parent_hash {
            return Err(XtError::InvalidAssuranceParentHash(
                entry.anchor_parent_hash.encode_hex(),
                header_parent_hash.encode_hex(),
                entry.validator_index,
            ));
        }

        // Verify the signature
        let mut buf = vec![];
        header_parent_hash.encode_to(&mut buf)?;
        entry
            .assuring_cores_bitvec
            .encode_to_fixed(&mut buf, CORE_COUNT)?;
        let hash = hash::<Blake2b256>(&buf[..])?;

        let mut message = Vec::with_capacity(X_A.len() + hash.len());
        message.extend_from_slice(X_A);
        message.extend_from_slice(hash.as_slice());

        let current_active_set = self.state_manager.get_active_set().await?;
        let assurer_public_key = current_active_set
            .get_validator_ed25519_key(entry.validator_index)
            .ok_or(XtError::InvalidValidatorIndex)?;

        let ed25519_verifier = Ed25519Verifier::new(*assurer_public_key);
        if !ed25519_verifier.verify_message(&message, &entry.signature) {
            return Err(XtError::InvalidAssuranceSignature(entry.validator_index));
        }

        // Validate the assuring cores bit-vec
        let pending_reports = self.state_manager.get_pending_reports().await?;
        for (core_index, bit) in entry.assuring_cores_bitvec.iter().enumerate() {
            // Cannot assure availability of a core without a pending report
            if bit && pending_reports.0[core_index].is_none() {
                return Err(XtError::NoPendingReportForCore(
                    core_index as CoreIndex,
                    entry.validator_index,
                ));
            }
        }

        Ok(())
    }
}
