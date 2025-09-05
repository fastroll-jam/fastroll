use crate::validation::error::XtError;
use fr_block::types::extrinsics::disputes::{
    Culprit, DisputesXt, Fault, Verdict, VerdictEvaluation,
};
use fr_common::{ByteEncodable, Hash32, X_0, X_1, X_G};
use fr_crypto::{
    signers::{ed25519::Ed25519Verifier, Verifier},
    types::Ed25519PubKey,
};
use fr_state::{
    manager::StateManager,
    types::{ActiveSet, PastSet, Timeslot, ValidatorSet},
};
use std::{collections::HashSet, sync::Arc};

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
pub struct DisputesXtValidator {
    state_manager: Arc<StateManager>,
}

impl DisputesXtValidator {
    pub fn new(state_manager: Arc<StateManager>) -> Self {
        Self { state_manager }
    }

    #[tracing::instrument(level = "debug", skip_all, name = "val_disputes_xt")]
    pub async fn validate(
        &self,
        extrinsic: &DisputesXt,
        prior_timeslot: &Timeslot,
    ) -> Result<(), XtError> {
        if extrinsic.verdicts.is_empty()
            && extrinsic.culprits.is_empty()
            && extrinsic.faults.is_empty()
        {
            return Ok(());
        }

        // Check if the entries are sorted
        if !extrinsic.verdicts.is_sorted() {
            return Err(XtError::VerdictsNotSorted);
        }
        if !extrinsic.culprits.is_sorted() {
            return Err(XtError::CulpritsNotSorted);
        }
        if !extrinsic.faults.is_sorted() {
            return Err(XtError::FaultsNotSorted);
        }

        // Used for duplicate validation
        let mut verdicts_hashes = HashSet::new();
        let mut culprits_keys = HashSet::new();
        let mut faults_keys = HashSet::new();

        let all_past_report_hashes = self
            .state_manager
            .get_disputes_clean()
            .await?
            .get_all_report_hashes();

        let active_set = self.state_manager.get_active_set_clean().await?;
        let past_set = self.state_manager.get_past_set_clean().await?;

        // Verdicts duplication check (report hash)
        let no_duplicate_verdicts = extrinsic
            .verdicts
            .iter()
            .all(|verdict| verdicts_hashes.insert(verdict.report_hash.clone()));
        if !no_duplicate_verdicts {
            return Err(XtError::DuplicateVerdict);
        }

        // Validate each verdict entry
        for verdict in extrinsic.verdicts.iter() {
            Self::validate_verdicts_entry(
                verdict,
                &active_set,
                &past_set,
                prior_timeslot,
                &all_past_report_hashes,
                extrinsic,
            )
            .await?;
        }

        if extrinsic.culprits.is_empty() && extrinsic.faults.is_empty() {
            return Ok(());
        }

        // Get the union of the ActiveSet and PastSet, then exclude any validators in the punish set.
        let punish_set = self.state_manager.get_disputes_clean().await?.punish_set;
        let valid_set =
            Self::union_active_and_past_exclude_punish(&active_set, &past_set, &punish_set);

        // Culprits duplication check (validator key)
        let no_duplicate_culprits = extrinsic
            .culprits
            .iter()
            .all(|culprit| culprits_keys.insert(culprit.validator_key.clone()));
        if !no_duplicate_culprits {
            return Err(XtError::DuplicateCulprit);
        }
        // Validate each culprit entry
        for culprit in extrinsic.culprits.iter() {
            Self::validate_culprits_entry(culprit, &valid_set, &punish_set, extrinsic)?;
        }

        // Faults duplication check (validator key)
        let no_duplicate_faults = extrinsic
            .faults
            .iter()
            .all(|fault| faults_keys.insert(fault.validator_key.clone()));
        if !no_duplicate_faults {
            return Err(XtError::DuplicateFault);
        }
        // Validate each fault entry
        for fault in extrinsic.faults.iter() {
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

    #[tracing::instrument(level = "debug", skip_all)]
    async fn validate_verdicts_entry(
        entry: &Verdict,
        active_set: &ActiveSet,
        past_set: &PastSet,
        prior_timeslot: &Timeslot,
        all_past_report_hashes: &[Hash32],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtError> {
        // Check if verdicts contain entries with epoch index older than the previous epoch
        if entry.epoch_index + 1 < prior_timeslot.epoch() {
            return Err(XtError::InvalidJudgmentsAge(
                entry.epoch_index,
                prior_timeslot.epoch(),
            ));
        }

        // Check the valid votes count
        if let VerdictEvaluation::Invalid(positive_votes) = entry.evaluate_verdict() {
            return Err(XtError::InvalidVotesCount(positive_votes));
        }

        // Check the valid votes count and ensure that the minimum number of culprits or faults
        // corresponding to the verdict is included in the extrinsic.
        match entry.evaluate_verdict() {
            VerdictEvaluation::Invalid(positive_votes) => {
                return Err(XtError::InvalidVotesCount(positive_votes))
            }
            VerdictEvaluation::IsGood => {
                if extrinsic.count_faults_with_report_hash(&entry.report_hash) < 1 {
                    return Err(XtError::NotEnoughFault(entry.report_hash.encode_hex()));
                }
            }
            VerdictEvaluation::IsBad => {
                if extrinsic.count_culprits_with_report_hash(&entry.report_hash) < 2 {
                    return Err(XtError::NotEnoughCulprit(entry.report_hash.encode_hex()));
                }
            }
            _ => (),
        }

        // Verdicts entry must not be present in any past report hashes - neither in the `GoodSet`,
        // `BadSet`, nor `WonkySet`.
        if all_past_report_hashes.contains(&entry.report_hash) {
            return Err(XtError::VerdictAlreadyExists);
        }

        // Check if judgments are sorted
        if !entry.judgments.iter().is_sorted() {
            return Err(XtError::JudgmentsNotSorted);
        }

        // Check for duplicate entry
        let mut voters_set = HashSet::new();
        let no_duplicate_judgments = entry
            .judgments
            .iter()
            .all(|judgment| voters_set.insert(judgment.voter));
        if !no_duplicate_judgments {
            return Err(XtError::DuplicateJudgment);
        }

        let validator_set = if entry.epoch_index == prior_timeslot.epoch() {
            &active_set.0
        } else {
            &past_set.0
        };

        let positive_message = [X_1, entry.report_hash.as_slice()].concat();
        let negative_message = [X_0, entry.report_hash.as_slice()].concat();

        // Verify the judgment signatures
        for judgment in entry.judgments.iter() {
            let message = if judgment.is_report_valid {
                &positive_message
            } else {
                &negative_message
            };
            let voter_public_key = validator_set
                .get_validator_ed25519_key(judgment.voter)
                .ok_or(XtError::InvalidValidatorIndex)?;
            let ed25519_verifier = Ed25519Verifier::new(voter_public_key.clone());
            ed25519_verifier
                .verify_message(message, &judgment.voter_signature)
                .map_err(|_| XtError::InvalidJudgmentSignature(judgment.voter))?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    fn validate_culprits_entry(
        entry: &Culprit,
        valid_set: &HashSet<Ed25519PubKey>,
        punish_set: &[Ed25519PubKey],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtError> {
        // Check if the culprit is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(XtError::CulpritAlreadyReported(
                entry.validator_key.to_hex(),
            ));
        }

        // Check the verdict entry that corresponds to the fault entry exists, and it is actually "bad".
        let verdict = extrinsic
            .get_verdict_by_report_hash(&entry.report_hash)
            .ok_or(XtError::InvalidCulpritReportHash(
                entry.validator_key.to_hex(),
            ))?;
        if !matches!(verdict.evaluate_verdict(), VerdictEvaluation::IsBad) {
            return Err(XtError::NotCulprit(entry.validator_key.to_hex()));
        }

        if !valid_set.contains(&entry.validator_key) {
            return Err(XtError::InvalidCulpritsGuarantorKey(
                entry.validator_key.to_hex(),
            ));
        }

        // Verify the signature
        let hash = &entry.report_hash;
        let message = [X_G, hash.as_slice()].concat();

        let ed25519_verifier = Ed25519Verifier::new(entry.validator_key.clone());
        ed25519_verifier
            .verify_message(&message, &entry.signature)
            .map_err(|_| XtError::InvalidCulpritSignature(entry.validator_key.to_hex()))?;
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    pub fn validate_faults_entry(
        entry: &Fault,
        valid_set: &HashSet<Ed25519PubKey>,
        punish_set: &[Ed25519PubKey],
        extrinsic: &DisputesXt,
    ) -> Result<(), XtError> {
        // Check if the culprit is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(XtError::FaultAlreadyReported(entry.validator_key.to_hex()));
        }

        // Verdict entry that corresponds to the fault entry
        let verdict_entry = extrinsic
            .get_verdict_by_report_hash(&entry.report_hash)
            .ok_or(XtError::InvalidFaultReportHash(
                entry.validator_key.to_hex(),
            ))?;

        let is_fault = match verdict_entry.evaluate_verdict() {
            VerdictEvaluation::IsGood => !entry.is_report_valid,
            VerdictEvaluation::IsBad => entry.is_report_valid,
            _ => false,
        };

        if !is_fault {
            return Err(XtError::NotFault(entry.validator_key.to_hex()));
        }

        if !valid_set.contains(&entry.validator_key) {
            return Err(XtError::InvalidFaultsAuditorKey(
                entry.validator_key.to_hex(),
            ));
        }

        // Verify the signature
        let message = if entry.is_report_valid {
            [X_1, entry.report_hash.as_slice()].concat()
        } else {
            [X_0, entry.report_hash.as_slice()].concat()
        };

        let ed25519_verifier = Ed25519Verifier::new(entry.validator_key.clone());
        ed25519_verifier
            .verify_message(&message, &entry.signature)
            .map_err(|_| XtError::InvalidFaultSignature(entry.validator_key.to_hex()))?;
        Ok(())
    }
}
