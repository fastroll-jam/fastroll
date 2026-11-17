use crate::validation::error::XtError;
use fr_block::types::extrinsics::disputes::{
    Culprit, DisputesXt, Fault, Verdict, VerdictEvaluation,
};
use fr_common::{
    validators_super_majority, ByteEncodable, Hash32, WorkReportHash, MAX_OFFENSES_PER_EXTRINSIC,
    MAX_VERDICTS_PER_EXTRINSIC, X_0, X_1, X_G,
};
use fr_crypto::{
    signers::{ed25519::Ed25519Verifier, Verifier},
    types::Ed25519PubKey,
};
use fr_state::{
    manager::StateManager,
    types::{ActiveSet, DisputesState, PastSet, Timeslot, ValidatorSet},
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
/// - `verdicts` may have at most `MAX_VERDICTS_PER_EXTRINSIC` (`M_V`) entries.
/// - `culprits` and `faults` may each have at most `MAX_OFFENSES_PER_EXTRINSIC` (`M_O`) entries.
///
/// ## Entry Validation
/// - No duplicate work-report hashes are allowed within the extrinsic or among any previously reported hashes.
/// - `verdicts`
///     - All `voter_signature`s in `judgments` must be valid Ed25519 signatures of the work report
///       hash, signed by the corresponding public keys of the `voter`s,
///       which must be part of either the `ActiveSet` or the `PastSet`.
///     - `epoch_index` of verdicts must match either the current epoch or the previous epoch.
///     - Each verdict entry must have exactly `⌊2/3|k|⌋ + 1` judgments, where `k` is the `ActiveSet` for
///       the current epoch and the `PastSet` for the previous epoch.
///     - Its positive judgments must be zero, `⌊|k|/3⌋`, or all of them.
/// - `culprits` and `faults`
///     - Offender signatures must be valid Ed25519 signatures of the work report hash,
///       similar to the validation of `verdicts`.
///     - Offenders already in the punish set (`ψ_O`) are rejected.
///     - They are judged against the posterior good and bad sets (`ψ'_G`, `ψ'_B`), which include reports judged in earlier blocks.
///     - A culprit's report must be in `ψ'_B`.
///     - A fault's report must be judged good or bad, and its vote must contradict that judgment (`r ∈ ψ'_B ⇔ r ∉ ψ'_G ⇔ v`).
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

        if extrinsic.verdicts.len() > MAX_VERDICTS_PER_EXTRINSIC {
            return Err(XtError::VerdictsEntryLimitExceeded(
                extrinsic.verdicts.len(),
                MAX_VERDICTS_PER_EXTRINSIC,
            ));
        }
        if extrinsic.culprits.len() > MAX_OFFENSES_PER_EXTRINSIC {
            return Err(XtError::CulpritsEntryLimitExceeded(
                extrinsic.culprits.len(),
                MAX_OFFENSES_PER_EXTRINSIC,
            ));
        }
        if extrinsic.faults.len() > MAX_OFFENSES_PER_EXTRINSIC {
            return Err(XtError::FaultsEntryLimitExceeded(
                extrinsic.faults.len(),
                MAX_OFFENSES_PER_EXTRINSIC,
            ));
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

        let prior_disputes = self.state_manager.get_disputes_clean().await?;
        let all_past_report_hashes = prior_disputes.get_all_report_hashes();

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
        let punish_set = &prior_disputes.punish_set;
        let valid_set =
            Self::union_active_and_past_exclude_punish(&active_set, &past_set, punish_set);
        let posterior_report_sets = PosteriorReportSets::new(&prior_disputes, extrinsic);

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
            Self::validate_culprits_entry(culprit, &valid_set, punish_set, &posterior_report_sets)?;
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
            Self::validate_faults_entry(fault, &valid_set, punish_set, &posterior_report_sets)?;
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

        // `k`: The validator set that signs the verdict epoch.
        let validator_set = if entry.epoch_index == prior_timeslot.epoch() {
            &active_set.0
        } else {
            &past_set.0
        };

        // Check the judgments count
        let expected_judgments_count = validators_super_majority(validator_set.len());
        if entry.judgments.len() != expected_judgments_count {
            return Err(XtError::InvalidJudgmentsCount(
                entry.judgments.len(),
                expected_judgments_count,
            ));
        }

        // Check the valid votes count
        if let VerdictEvaluation::Invalid(positive_votes) = entry.evaluate_verdict() {
            return Err(XtError::InvalidVotesCount(positive_votes));
        }

        // Check the valid votes count and that a good verdict has at least one fault in the extrinsic.
        // A bad verdict needs no culprits.
        match entry.evaluate_verdict() {
            VerdictEvaluation::Invalid(positive_votes) => {
                return Err(XtError::InvalidVotesCount(positive_votes))
            }
            VerdictEvaluation::IsGood
                if extrinsic.count_faults_with_report_hash(&entry.report_hash) < 1 =>
            {
                return Err(XtError::NotEnoughFault(entry.report_hash.encode_hex()));
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
        posterior_report_sets: &PosteriorReportSets,
    ) -> Result<(), XtError> {
        // Check if the culprit is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(XtError::CulpritAlreadyReported(
                entry.validator_key.to_hex(),
            ));
        }

        // `r ∈ ψ'_B`, where the report may have been judged bad in this block or an earlier one
        if !posterior_report_sets.bad_set.contains(&entry.report_hash) {
            return Err(XtError::InvalidCulpritReportHash(
                entry.validator_key.to_hex(),
            ));
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
    fn validate_faults_entry(
        entry: &Fault,
        valid_set: &HashSet<Ed25519PubKey>,
        punish_set: &[Ed25519PubKey],
        posterior_report_sets: &PosteriorReportSets,
    ) -> Result<(), XtError> {
        // Check if the fault is already in the punish set
        if punish_set.contains(&entry.validator_key) {
            return Err(XtError::FaultAlreadyReported(entry.validator_key.to_hex()));
        }

        // `r ∈ ψ'_B ⇔ r ∉ ψ'_G ⇔ v`, so the report is judged good or bad and the vote contradicts it.
        // An unjudged or wonky report is in neither set and never satisfies it.
        let is_report_bad = posterior_report_sets.bad_set.contains(&entry.report_hash);
        let is_report_good = posterior_report_sets.good_set.contains(&entry.report_hash);
        if is_report_bad == is_report_good || is_report_bad != entry.is_report_valid {
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

/// Report hash sets `ψ'_G` and `ψ'_B` after the verdicts of a disputes extrinsic, used to judge its culprits and faults.
struct PosteriorReportSets {
    /// `ψ'_G`: The prior good set plus the reports this extrinsic judges good
    good_set: HashSet<WorkReportHash>,
    /// `ψ'_B`: The prior bad set plus the reports this extrinsic judges bad
    bad_set: HashSet<WorkReportHash>,
}

impl PosteriorReportSets {
    /// Adds the good and bad verdicts of `extrinsic` to the prior good and bad sets of `prior_disputes`.
    fn new(prior_disputes: &DisputesState, extrinsic: &DisputesXt) -> Self {
        let (new_good_set, new_bad_set, _) = extrinsic.split_report_set();
        Self {
            good_set: prior_disputes
                .good_set
                .iter()
                .cloned()
                .chain(new_good_set)
                .collect(),
            bad_set: prior_disputes
                .bad_set
                .iter()
                .cloned()
                .chain(new_bad_set)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr_block::types::extrinsics::disputes::{Judgment, Judgments};
    use fr_crypto::{
        signers::{ed25519::Ed25519Signer, Signer},
        types::{Ed25519SecretKey, Ed25519Sig},
    };
    use std::error::Error;

    /// Ed25519 key pair of RFC 8032 test 1.
    const OFFENDER_SECRET_KEY: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const OFFENDER_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn offender_key() -> Result<Ed25519PubKey, Box<dyn Error>> {
        Ok(Ed25519PubKey::from_slice(&hex::decode(
            OFFENDER_PUBLIC_KEY,
        )?)?)
    }

    fn offender_signature(message: &[u8]) -> Result<Ed25519Sig, Box<dyn Error>> {
        let secret_key = Ed25519SecretKey::from_slice(&hex::decode(OFFENDER_SECRET_KEY)?)?;
        Ok(Ed25519Signer::new(secret_key).sign_message(message)?)
    }

    fn report_hash(byte: u8) -> WorkReportHash {
        WorkReportHash::new([byte; 32])
    }

    fn verdict(report_hash: WorkReportHash, votes: &[bool]) -> Result<Verdict, Box<dyn Error>> {
        let judgments = votes
            .iter()
            .enumerate()
            .map(|(voter, &is_report_valid)| Judgment {
                is_report_valid,
                voter: voter as u16,
                voter_signature: Ed25519Sig::default(),
            })
            .collect::<Vec<_>>();
        Ok(Verdict {
            report_hash,
            epoch_index: 0,
            judgments: Judgments::try_from(judgments)?,
        })
    }

    fn signed_culprit(report_hash: WorkReportHash) -> Result<Culprit, Box<dyn Error>> {
        let signature = offender_signature(&[X_G, report_hash.as_slice()].concat())?;
        Ok(Culprit {
            report_hash,
            validator_key: offender_key()?,
            signature,
        })
    }

    fn signed_fault(
        report_hash: WorkReportHash,
        is_report_valid: bool,
    ) -> Result<Fault, Box<dyn Error>> {
        let context = if is_report_valid { X_1 } else { X_0 };
        let signature = offender_signature(&[context, report_hash.as_slice()].concat())?;
        Ok(Fault {
            report_hash,
            is_report_valid,
            validator_key: offender_key()?,
            signature,
        })
    }

    /// Posterior sets where report 1 is good and report 2 is bad.
    fn posterior_report_sets() -> PosteriorReportSets {
        PosteriorReportSets {
            good_set: HashSet::from([report_hash(1)]),
            bad_set: HashSet::from([report_hash(2)]),
        }
    }

    fn valid_set() -> Result<HashSet<Ed25519PubKey>, Box<dyn Error>> {
        Ok(HashSet::from([offender_key()?]))
    }

    mod posterior_report_sets_tests {
        use super::*;

        #[test]
        fn test_posterior_report_sets_include_prior_and_new_verdicts() -> Result<(), Box<dyn Error>>
        {
            let prior_disputes = DisputesState {
                good_set: vec![report_hash(1)],
                bad_set: vec![report_hash(2)],
                wonky_set: vec![report_hash(3)],
                punish_set: vec![],
            };
            let extrinsic = DisputesXt {
                verdicts: vec![
                    verdict(report_hash(4), &[true, true, true])?,
                    verdict(report_hash(5), &[false, false, false])?,
                    verdict(report_hash(6), &[true, false, false])?,
                ],
                ..Default::default()
            };

            let sets = PosteriorReportSets::new(&prior_disputes, &extrinsic);
            assert_eq!(
                sets.good_set,
                HashSet::from([report_hash(1), report_hash(4)])
            );
            assert_eq!(
                sets.bad_set,
                HashSet::from([report_hash(2), report_hash(5)])
            );
            Ok(())
        }
    }

    mod validate_culprits_entry_tests {
        use super::*;

        #[test]
        fn test_culprit_on_bad_report() -> Result<(), Box<dyn Error>> {
            let culprit = signed_culprit(report_hash(2))?;
            DisputesXtValidator::validate_culprits_entry(
                &culprit,
                &valid_set()?,
                &[],
                &posterior_report_sets(),
            )?;
            Ok(())
        }

        #[test]
        fn test_culprit_on_report_not_bad() -> Result<(), Box<dyn Error>> {
            // A good report and an unjudged report
            for report in [report_hash(1), report_hash(9)] {
                let culprit = signed_culprit(report)?;
                let result = DisputesXtValidator::validate_culprits_entry(
                    &culprit,
                    &valid_set()?,
                    &[],
                    &posterior_report_sets(),
                );
                assert!(matches!(result, Err(XtError::InvalidCulpritReportHash(_))));
            }
            Ok(())
        }
    }

    mod validate_faults_entry_tests {
        use super::*;

        #[test]
        fn test_fault_vote_contradicting_judgment() -> Result<(), Box<dyn Error>> {
            // A valid vote on a bad report and an invalid vote on a good report
            for (report, is_report_valid) in [(report_hash(2), true), (report_hash(1), false)] {
                let fault = signed_fault(report, is_report_valid)?;
                DisputesXtValidator::validate_faults_entry(
                    &fault,
                    &valid_set()?,
                    &[],
                    &posterior_report_sets(),
                )?;
            }
            Ok(())
        }

        #[test]
        fn test_fault_vote_agreeing_or_on_unjudged_report() -> Result<(), Box<dyn Error>> {
            let cases = [
                ("invalid vote on a bad report", report_hash(2), false),
                ("valid vote on a good report", report_hash(1), true),
                (
                    "invalid vote on an unjudged or wonky report",
                    report_hash(9),
                    false,
                ),
                (
                    "valid vote on an unjudged or wonky report",
                    report_hash(9),
                    true,
                ),
            ];
            for (case, report, is_report_valid) in cases {
                let fault = signed_fault(report, is_report_valid)?;
                let result = DisputesXtValidator::validate_faults_entry(
                    &fault,
                    &valid_set()?,
                    &[],
                    &posterior_report_sets(),
                );
                assert!(
                    matches!(result, Err(XtError::NotFault(_))),
                    "{case}: {result:?}"
                );
            }
            Ok(())
        }
    }
}
