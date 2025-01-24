use crate::asn_types::disputes::DisputesErrorCode;
use rjam_extrinsics::validation::error::XtValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> DisputesErrorCode {
    match e {
        TransitionError::XtValidationError(VerdictAlreadyExists) => {
            DisputesErrorCode::already_judged
        }
        TransitionError::XtValidationError(VerdictsNotSorted)
        | TransitionError::XtValidationError(DuplicateVerdict) => {
            DisputesErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::XtValidationError(JudgmentsNotSorted)
        | TransitionError::XtValidationError(DuplicateJudgment) => {
            DisputesErrorCode::judgements_not_sorted_unique
        }
        TransitionError::XtValidationError(CulpritsNotSorted)
        | TransitionError::XtValidationError(DuplicateCulprit) => {
            DisputesErrorCode::culprits_not_sorted_unique
        }
        TransitionError::XtValidationError(FaultsNotSorted)
        | TransitionError::XtValidationError(DuplicateFault) => {
            DisputesErrorCode::faults_not_sorted_unique
        }
        TransitionError::XtValidationError(InvalidJudgmentSignature(_))
        | TransitionError::XtValidationError(InvalidCulpritSignature(_))
        | TransitionError::XtValidationError(InvalidFaultSignature(_)) => {
            DisputesErrorCode::bad_signature
        }
        TransitionError::XtValidationError(NotFault(_)) => DisputesErrorCode::fault_verdict_wrong,
        TransitionError::XtValidationError(InvalidJudgmentsAge(_, _)) => {
            DisputesErrorCode::bad_judgement_age
        }
        TransitionError::XtValidationError(NotEnoughCulprit(_)) => {
            DisputesErrorCode::not_enough_culprits
        }
        TransitionError::XtValidationError(NotEnoughFault(_)) => {
            DisputesErrorCode::not_enough_faults
        }
        TransitionError::XtValidationError(InvalidVotesCount(_)) => {
            DisputesErrorCode::bad_vote_split
        }
        TransitionError::XtValidationError(InvalidCulpritReportHash(_)) => {
            DisputesErrorCode::culprits_verdict_not_bad
        }
        TransitionError::XtValidationError(CulpritAlreadyReported(_))
        | TransitionError::XtValidationError(FaultAlreadyReported(_)) => {
            DisputesErrorCode::offender_already_reported
        }
        _ => DisputesErrorCode::reserved,
    }
}
