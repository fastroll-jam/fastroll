use crate::validation::error::{XtValidationError, XtValidationError::*};
use rjam_common::{Ed25519PubKey, Hash32, HASH_SIZE, X_0, X_1, X_G};
use rjam_crypto::verify_signature;
use rjam_state::StateManager;
use rjam_types::{
    extrinsics::disputes::{Culprit, DisputesXt, Fault, Verdict, VerdictEvaluation},
    state::*,
};
use std::collections::HashSet;

/// Validates contents of `DisputesXt` type.
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
///     - `epoch_index` of verdicts must match either the current epoch or the previous epoch.
///     - Judgments of each verdict entry must have one of the following valid vote counts for the
///       target work report: zero, `FLOOR_ONE_THIRDS_VALIDATOR_COUNT`, or `VALIDATORS_SUPER_MAJORITY`.
/// - `culprits` and `faults`
///     - Offender signatures must be valid Ed25519 signatures of the work report hash,
///       similar to the validation of `verdicts`.
///     - Offenders whose work reports are already in the punish-set must be excluded.
pub struct DisputesXtValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> DisputesXtValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    pub async fn validate(
        &self,
        extrinsic: &DisputesXt,
        prior_timeslot: &Timeslot,
    ) -> Result<(), XtValidationError> {
        // Check if the entries are sorted
        if !extrinsic.verdicts.is_sorted() {
            return Err(VerdictsNotSorted);
        }
        if !extrinsic.culprits.is_sorted() {
            return Err(CulpritsNotSorted);
        }
        if !extrinsic.faults.is_sorted() {
            return Err(FaultsNotSorted);
        }

        // Used for duplicate validation
        let mut verdicts_hashes = HashSet::new();
        let mut culprits_hashes = HashSet::new();
        let mut faults_hashes = HashSet::new();

        let all_past_report_hashes = self
            .state_manager
            .get_disputes()
            .await?
            .get_all_report_hashes();

        // Validate each verdict entry
        for verdict in extrinsic.verdicts.iter() {
            // Check for duplicate entry (report_hash)
            if !verdicts_hashes.insert(verdict.report_hash) {
                return Err(DuplicateVerdict);
            }

            self.validate_verdicts_entry(
                verdict,
                prior_timeslot,
                &all_past_report_hashes,
                extrinsic,
            )
            .await?;
        }

        // Get the union of the ActiveSet and PastSet, then exclude any validators in the punish set.
        let active_set = self.state_manager.get_active_set().await?;
        let past_set = self.state_manager.get_past_set().await?;
        let punish_set = self.state_manager.get_disputes().await?.punish_set;
        let valid_set =
            Self::union_active_and_past_exclude_punish(&active_set, &past_set, &punish_set);

        // Validate each culprit entry
        for culprit in extrinsic.culprits.iter() {
            // Check for duplicate entry (validator_key)
            if !culprits_hashes.insert(culprit.validator_key) {
                return Err(DuplicateCulprit);
            }

            Self::validate_culprits_entry(culprit, &valid_set, &punish_set, extrinsic)?;
        }

        // Validate each fault entry
        for fault in extrinsic.faults.iter() {
            // Check for duplicate entry (validator_key)
            if !faults_hashes.insert(fault.validator_key) {
                return Err(DuplicateFault);
            }

            Self::validate_faults_entry(fault, &valid_set, &punish_set, extrinsic)?;
        }

        Ok(())
    }

    fn union_active_and_past_exclude_punish(
        active_set: &ActiveSet,
        past_set: &PastSet,
        punish_set: &[Ed25519PubKey],
    ) -> HashSet<Ed25519PubKey> {
        let active_keys = active_set.ed25519_keys_set();
        let past_keys = past_set.ed25519_keys_set();

        let mut active_and_past_keys: HashSet<Ed25519PubKey> =
            active_keys.union(&past_keys).cloned().collect();
        for key in punish_set {
            active_and_past_keys.remove(key);
        }

        active_and_past_keys
    }

    pub async fn validate_verdicts_entry(
        &self,
        entry: &Verdict,
        prior_timeslot: &Timeslot,
        all_past_report_hashes: &[Hash32],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtValidationError> {
        // Check if verdicts contain entries with epoch index older the previous epoch
        if entry.epoch_index + 1 < prior_timeslot.epoch() {
            return Err(InvalidJudgmentsAge(
                entry.epoch_index,
                prior_timeslot.epoch(),
            ));
        }

        // Check the valid votes count
        if let VerdictEvaluation::Invalid(positive_votes) = entry.evaluate_verdict() {
            return Err(InvalidVotesCount(positive_votes));
        }

        // Check the valid votes count and ensure that the minimum number of culprits or faults
        // corresponding to the verdict is included in the extrinsic.
        match entry.evaluate_verdict() {
            VerdictEvaluation::Invalid(positive_votes) => {
                return Err(InvalidVotesCount(positive_votes))
            }
            VerdictEvaluation::IsGood => {
                if extrinsic.count_faults_with_report_hash(&entry.report_hash) < 1 {
                    return Err(NotEnoughFault(entry.report_hash.encode_hex()));
                }
            }
            VerdictEvaluation::IsBad => {
                if extrinsic.count_culprits_with_report_hash(&entry.report_hash) < 2 {
                    return Err(NotEnoughCulprit(entry.report_hash.encode_hex()));
                }
            }
            _ => (),
        }

        // Verdicts entry must not be present in any past report hashes - neither in the `GoodSet`,
        // `BadSet`, nor `WonkySet`.
        if all_past_report_hashes.contains(&entry.report_hash) {
            return Err(VerdictAlreadyExists);
        }

        // Check if judgments are sorted
        if !entry.judgments.is_sorted() {
            return Err(JudgmentsNotSorted);
        }

        // Check for duplicate entry
        let mut voters_set = HashSet::new();
        for judgment in entry.judgments.iter() {
            if !voters_set.insert(judgment.voter) {
                return Err(DuplicateJudgment);
            }
        }

        // TODO: Move this outside of this method, remove `&self` param
        let validator_set = if entry.epoch_index == prior_timeslot.epoch() {
            self.state_manager.get_active_set().await?.0
        } else {
            self.state_manager.get_past_set().await?.0
        };

        let mut positive_message = Vec::with_capacity(X_1.len() + HASH_SIZE);
        positive_message.extend_from_slice(X_1);
        positive_message.extend_from_slice(entry.report_hash.as_slice());
        let mut negative_message = Vec::with_capacity(X_0.len() + HASH_SIZE);
        negative_message.extend_from_slice(X_0);
        negative_message.extend_from_slice(entry.report_hash.as_slice());

        for judgment in entry.judgments.iter() {
            let message = if judgment.is_report_valid {
                &positive_message
            } else {
                &negative_message
            };

            let voter_public_key =
                get_validator_ed25519_key_by_index(&validator_set, judgment.voter)
                    .map_err(|_| InvalidValidatorIndex)?;

            if !verify_signature(message, &voter_public_key, &judgment.voter_signature) {
                return Err(InvalidJudgmentSignature(judgment.voter));
            }
        }

        Ok(())
    }

    pub fn validate_culprits_entry(
        entry: &Culprit,
        valid_set: &HashSet<Ed25519PubKey>,
        punish_set: &[Ed25519PubKey],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtValidationError> {
        // Check if the culprit is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(CulpritAlreadyReported(entry.validator_key.encode_hex()));
        }

        // Check the verdict entry that corresponds to the fault entry exists
        extrinsic
            .get_verdict_by_report_hash(&entry.report_hash)
            .ok_or(InvalidCulpritReportHash(entry.validator_key.encode_hex()))?;

        if !valid_set.contains(&entry.validator_key) {
            return Err(InvalidValidatorKeySet(entry.validator_key.encode_hex()));
        }

        // FIXME: check the message (X_G?)
        // Validate the signature
        let hash = &entry.report_hash;
        let mut message = Vec::with_capacity(X_G.len() + hash.len());
        message.extend_from_slice(X_G);
        message.extend_from_slice(hash.as_slice());

        if !verify_signature(&message, &entry.validator_key, &entry.signature) {
            return Err(InvalidCulpritSignature(entry.validator_key.encode_hex()));
        }

        Ok(())
    }

    pub fn validate_faults_entry(
        entry: &Fault,
        valid_set: &HashSet<Ed25519PubKey>,
        punish_set: &[Ed25519PubKey],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtValidationError> {
        // Check if the culprit is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(FaultAlreadyReported(entry.validator_key.encode_hex()));
        }

        // Verdict entry that corresponds to the fault entry
        let verdict_entry = extrinsic
            .get_verdict_by_report_hash(&entry.report_hash)
            .ok_or(InvalidFaultReportHash(entry.validator_key.encode_hex()))?;

        let is_fault = match verdict_entry.evaluate_verdict() {
            VerdictEvaluation::IsGood => !entry.is_report_valid,
            VerdictEvaluation::IsBad => entry.is_report_valid,
            _ => false,
        };

        if !is_fault {
            return Err(NotFault(entry.validator_key.encode_hex()));
        }

        if !valid_set.contains(&entry.validator_key) {
            return Err(InvalidValidatorKeySet(entry.validator_key.encode_hex()));
        }

        // Validate the signature
        let message = if entry.is_report_valid {
            let mut _message = Vec::with_capacity(X_1.len() + HASH_SIZE);
            _message.extend_from_slice(X_1);
            _message.extend_from_slice(entry.report_hash.as_slice());
            _message
        } else {
            let mut _message = Vec::with_capacity(X_0.len() + HASH_SIZE);
            _message.extend_from_slice(X_0);
            _message.extend_from_slice(entry.report_hash.as_slice());
            _message
        };

        if !verify_signature(&message, &entry.validator_key, &entry.signature) {
            return Err(InvalidFaultSignature(entry.validator_key.encode_hex()));
        }

        Ok(())
    }
}
