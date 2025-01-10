use crate::asn_types::disputes::DisputesErrorCode;
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> DisputesErrorCode {
    match e {
        TransitionError::ExtrinsicValidationError(VerdictAlreadyExists) => {
            DisputesErrorCode::already_judged
        }
        TransitionError::ExtrinsicValidationError(VerdictsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateVerdict) => {
            DisputesErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(JudgmentsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateJudgment) => {
            DisputesErrorCode::judgements_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(CulpritsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateCulprit) => {
            DisputesErrorCode::culprits_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(FaultsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateFault) => {
            DisputesErrorCode::faults_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(InvalidJudgmentSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidCulpritSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidFaultSignature(_)) => {
            DisputesErrorCode::bad_signature
        }
        TransitionError::ExtrinsicValidationError(NotFault(_)) => {
            DisputesErrorCode::fault_verdict_wrong
        }
        TransitionError::ExtrinsicValidationError(InvalidJudgmentsAge(_, _)) => {
            DisputesErrorCode::bad_judgement_age
        }
        TransitionError::ExtrinsicValidationError(NotEnoughCulprit(_)) => {
            DisputesErrorCode::not_enough_culprits
        }
        TransitionError::ExtrinsicValidationError(NotEnoughFault(_)) => {
            DisputesErrorCode::not_enough_faults
        }
        TransitionError::ExtrinsicValidationError(InvalidVotesCount(_)) => {
            DisputesErrorCode::bad_vote_split
        }
        TransitionError::ExtrinsicValidationError(InvalidCulpritReportHash(_)) => {
            DisputesErrorCode::culprits_verdict_not_bad
        }
        TransitionError::ExtrinsicValidationError(CulpritAlreadyReported(_))
        | TransitionError::ExtrinsicValidationError(FaultAlreadyReported(_)) => {
            DisputesErrorCode::offender_already_reported
        }
        _ => DisputesErrorCode::reserved,
    }
}
