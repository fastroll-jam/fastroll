#![allow(dead_code)]
use crate::validation::error::ExtrinsicValidationError;
use rjam_common::{Ed25519PubKey, Hash32, HASH_SIZE, X_0, X_1, X_G};
use rjam_crypto::verify_signature;
use rjam_state::StateManager;
use rjam_types::{
    extrinsics::{
        disputes::{Culprit, DisputesExtrinsic, Fault, Verdict},
        ExtrinsicsError,
    },
    state::{
        timeslot::Timeslot,
        validators::{get_validator_ed25519_key_by_index, ActiveSet, PastSet},
    },
};
use std::collections::HashSet;

/// Validates contents of `DisputesExtrinsic` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Entries in `verdicts` must be ordered by the report hash.
///   - Entries in `judgments` within each verdict must be ordered by the `validator_index` of the voters.
/// - Offender signatures in `culprits` and `faults` must be ordered by the validator's Ed25519 key.
///
/// ## Length Limit
/// - No length limit applies.
///
/// ## Entry Validation
/// - No duplicate work-report hashes are allowed within the extrinsic or among any previously reported hashes.
/// - `verdicts`
///     - All `voter_signature`s in `judgments` must be valid Ed25519 signatures of the work report
///       hash, signed by the corresponding public keys of the `voter`s,
///       which must be part of either the `ActiveSet` or the `PastSet`.
/// - `culprits` and `faults`
///     - Offender signatures must be valid Ed25519 signatures of the work report hash,
///       similar to the validation of `verdicts`.
///     - Offenders whose work reports are already in the punish-set must be excluded.
pub struct DisputesExtrinsicValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> DisputesExtrinsicValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    pub fn validate(
        &self,
        extrinsic: &DisputesExtrinsic,
        prior_timeslot: &Timeslot,
    ) -> Result<bool, ExtrinsicValidationError> {
        // For duplicate validation
        let mut verdicts_hashes = HashSet::new();
        let mut culprits_hashes = HashSet::new();
        let mut faults_hashes = HashSet::new();

        // Check if the entries are sorted
        if !extrinsic.verdicts.is_sorted()
            || !extrinsic.culprits.is_sorted()
            || !extrinsic.faults.is_sorted()
        {
            return Ok(false);
        }

        // Validate each verdicts entry
        let all_past_report_hashes = self.state_manager.get_disputes()?.get_all_report_hashes();

        let all_verdicts_valid = extrinsic.verdicts.iter().all(|verdict| {
            // Check for duplicate entry (report_hash)
            if !verdicts_hashes.insert(verdict.report_hash) {
                return false;
            }
            matches!(
                self.validate_verdicts_entry(verdict, prior_timeslot, &all_past_report_hashes),
                Ok(true)
            )
        });
        if !all_verdicts_valid {
            return Ok(false);
        }

        // Get the union of the ActiveSet and PastSet, then exclude any validators in the punish set.
        let active_set = self.state_manager.get_active_set()?;
        let past_set = self.state_manager.get_past_set()?;
        let punish_set = self.state_manager.get_disputes()?.punish_set;
        let valid_set =
            Self::union_active_and_past_exclude_punish(&active_set, &past_set, &punish_set);

        let current_bad_set = self.state_manager.get_disputes()?.bad_set;
        let current_good_set = self.state_manager.get_disputes()?.good_set;

        // Validate each culprits entry
        let all_culprits_valid = extrinsic.culprits.iter().all(|culprit| {
            // Check for duplicate entry (validator_key)
            if !culprits_hashes.insert(culprit.validator_key) {
                return false;
            }
            matches!(
                self.validate_culprits_entry(culprit, &current_bad_set, &valid_set),
                Ok(true)
            )
        });
        if !all_culprits_valid {
            return Ok(false);
        }

        // Validate each faults entry
        let all_faults_valid = extrinsic.faults.iter().all(|fault| {
            // Check for duplicate entry (validator_key)
            if !faults_hashes.insert(fault.validator_key) {
                return false;
            }
            matches!(
                self.validate_faults_entry(fault, &current_bad_set, &current_good_set, &valid_set),
                Ok(true)
            )
        });
        if !all_faults_valid {
            return Ok(false);
        }

        Ok(true)
    }

    fn union_active_and_past_exclude_punish(
        active_set: &ActiveSet,
        past_set: &PastSet,
        punish_set: &HashSet<Ed25519PubKey>,
    ) -> HashSet<Ed25519PubKey> {
        let active_keys = active_set.ed25519_keys();
        let past_keys = past_set.ed25519_keys();

        let mut active_and_past_keys: HashSet<Ed25519PubKey> =
            active_keys.union(&past_keys).cloned().collect();

        for key in punish_set {
            active_and_past_keys.remove(key);
        }

        active_and_past_keys
    }

    pub fn validate_verdicts_entry(
        &self,
        entry: &Verdict,
        prior_timeslot: &Timeslot,
        all_past_report_hashes: &HashSet<Hash32>,
    ) -> Result<bool, ExtrinsicValidationError> {
        // Verdicts entry must not be present in any past report hashes - neither in the `GoodSet`,
        // `BadSet`, nor `WonkySet`.
        if all_past_report_hashes.contains(&entry.report_hash) {
            return Ok(false);
        }

        // Check if judgments are sorted
        if !entry.judgments.is_sorted() {
            return Ok(false);
        }

        // Check for duplicate entry
        let mut voters_set = HashSet::new();
        for judgment in entry.judgments.iter() {
            if !voters_set.insert(judgment.voter) {
                return Ok(false);
            }
        }

        // TODO: Move this outside of this method.
        let validator_set = if entry.epoch_index == prior_timeslot.epoch() {
            self.state_manager.get_active_set()?.0
        } else {
            self.state_manager.get_past_set()?.0
        };

        let mut positive_message = Vec::with_capacity(X_1.len() + HASH_SIZE);
        positive_message.extend_from_slice(X_1);
        positive_message.extend_from_slice(&entry.report_hash);
        let mut negative_message = Vec::with_capacity(X_0.len() + HASH_SIZE);
        negative_message.extend_from_slice(X_0);
        negative_message.extend_from_slice(&entry.report_hash);

        for judgment in entry.judgments.iter() {
            let message = if judgment.is_report_valid {
                &positive_message
            } else {
                &negative_message
            };

            let voter_public_key =
                get_validator_ed25519_key_by_index(&validator_set, judgment.voter);

            if !verify_signature(message, &voter_public_key, &judgment.voter_signature) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn validate_culprits_entry(
        &self,
        entry: &Culprit,
        current_bad_set: &HashSet<Hash32>,
        valid_set: &HashSet<Ed25519PubKey>,
    ) -> Result<bool, ExtrinsicsError> {
        if !current_bad_set.contains(&entry.report_hash) {
            return Ok(false);
        }

        if !valid_set.contains(&entry.validator_key) {
            return Ok(false);
        }

        // Validate the signature
        let hash = &entry.report_hash;
        let mut message = Vec::with_capacity(X_G.len() + hash.len());
        message.extend_from_slice(X_G);
        message.extend_from_slice(hash);

        if !verify_signature(&message, &entry.validator_key, &entry.signature) {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn validate_faults_entry(
        &self,
        entry: &Fault,
        current_bad_set: &HashSet<Hash32>,
        current_good_set: &HashSet<Hash32>,
        valid_set: &HashSet<Ed25519PubKey>,
    ) -> Result<bool, ExtrinsicsError> {
        // Validate fails when the voter's vote was correct but the voter is in the faults set.
        if (entry.is_report_valid && current_good_set.contains(&entry.report_hash))
            || (!entry.is_report_valid && current_bad_set.contains(&entry.report_hash))
        {
            return Ok(false);
        }

        if !valid_set.contains(&entry.validator_key) {
            return Ok(false);
        }

        // Validate the signature
        let message = if entry.is_report_valid {
            let mut _message = Vec::with_capacity(X_1.len() + HASH_SIZE);
            _message.extend_from_slice(X_1);
            _message.extend_from_slice(&entry.report_hash);
            _message
        } else {
            let mut _message = Vec::with_capacity(X_0.len() + HASH_SIZE);
            _message.extend_from_slice(X_0);
            _message.extend_from_slice(&entry.report_hash);
            _message
        };

        if !verify_signature(&message, &entry.validator_key, &entry.signature) {
            return Ok(false);
        }

        Ok(true)
    }
}
