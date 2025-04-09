use crate::asn_types::disputes::DisputesErrorCode;
use rjam_extrinsics::validation::error::XtError;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> DisputesErrorCode {
    match e {
        TransitionError::XtValidationError(XtError::VerdictAlreadyExists) => {
            DisputesErrorCode::already_judged
        }
        TransitionError::XtValidationError(XtError::VerdictsNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicateVerdict) => {
            DisputesErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::XtValidationError(XtError::JudgmentsNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicateJudgment) => {
            DisputesErrorCode::judgements_not_sorted_unique
        }
        TransitionError::XtValidationError(XtError::CulpritsNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicateCulprit) => {
            DisputesErrorCode::culprits_not_sorted_unique
        }
        TransitionError::XtValidationError(XtError::FaultsNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicateFault) => {
            DisputesErrorCode::faults_not_sorted_unique
        }
        TransitionError::XtValidationError(XtError::InvalidJudgmentSignature(_))
        | TransitionError::XtValidationError(XtError::InvalidCulpritSignature(_))
        | TransitionError::XtValidationError(XtError::InvalidFaultSignature(_)) => {
            DisputesErrorCode::bad_signature
        }
        TransitionError::XtValidationError(XtError::NotFault(_)) => {
            DisputesErrorCode::fault_verdict_wrong
        }
        TransitionError::XtValidationError(XtError::InvalidJudgmentsAge(_, _)) => {
            DisputesErrorCode::bad_judgement_age
        }
        TransitionError::XtValidationError(XtError::NotEnoughCulprit(_)) => {
            DisputesErrorCode::not_enough_culprits
        }
        TransitionError::XtValidationError(XtError::NotEnoughFault(_)) => {
            DisputesErrorCode::not_enough_faults
        }
        TransitionError::XtValidationError(XtError::InvalidVotesCount(_)) => {
            DisputesErrorCode::bad_vote_split
        }
        TransitionError::XtValidationError(XtError::InvalidCulpritReportHash(_)) => {
            DisputesErrorCode::culprits_verdict_not_bad
        }
        TransitionError::XtValidationError(XtError::CulpritAlreadyReported(_))
        | TransitionError::XtValidationError(XtError::FaultAlreadyReported(_)) => {
            DisputesErrorCode::offender_already_reported
        }
        TransitionError::XtValidationError(XtError::InvalidCulpritsGuarantorKey(_)) => {
            DisputesErrorCode::bad_guarantor_key
        }
        TransitionError::XtValidationError(XtError::InvalidFaultsAuditorKey(_)) => {
            DisputesErrorCode::bad_auditor_key
        }
        _ => DisputesErrorCode::reserved,
    }
}
