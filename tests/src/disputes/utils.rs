use crate::disputes::asn_types::ErrorCode;
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> ErrorCode {
    match e {
        TransitionError::ExtrinsicValidationError(VerdictAlreadyExists) => {
            ErrorCode::already_judged
        }
        TransitionError::ExtrinsicValidationError(VerdictsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateVerdict) => {
            ErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(JudgmentsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateJudgment) => {
            ErrorCode::judgements_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(CulpritsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateCulprit) => {
            ErrorCode::culprits_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(FaultsNotSorted)
        | TransitionError::ExtrinsicValidationError(DuplicateFault) => {
            ErrorCode::faults_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(InvalidJudgmentSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidCulpritSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidFaultSignature(_)) => {
            ErrorCode::bad_signature
        }
        TransitionError::ExtrinsicValidationError(NotFault(_)) => ErrorCode::fault_verdict_wrong,
        TransitionError::ExtrinsicValidationError(InvalidJudgmentsAge(_, _)) => {
            ErrorCode::bad_judgement_age
        }
        TransitionError::ExtrinsicValidationError(NotEnoughCulprit(_)) => {
            ErrorCode::not_enough_culprits
        }
        TransitionError::ExtrinsicValidationError(NotEnoughFault(_)) => {
            ErrorCode::not_enough_faults
        }
        TransitionError::ExtrinsicValidationError(InvalidVotesCount(_)) => {
            ErrorCode::bad_vote_split
        }
        TransitionError::ExtrinsicValidationError(InvalidCulpritReportHash(_)) => {
            ErrorCode::culprits_verdict_not_bad
        }
        TransitionError::ExtrinsicValidationError(CulpritAlreadyReported(_))
        | TransitionError::ExtrinsicValidationError(FaultAlreadyReported(_)) => {
            ErrorCode::offender_already_reported
        }
        _ => ErrorCode::reserved,
    }
}
