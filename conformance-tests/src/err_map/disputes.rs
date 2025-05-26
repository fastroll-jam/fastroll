use crate::asn_types::disputes::DisputesErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> DisputesErrorCode {
    match e {
        TransitionError::XtError(XtError::VerdictAlreadyExists) => {
            DisputesErrorCode::already_judged
        }
        TransitionError::XtError(XtError::VerdictsNotSorted)
        | TransitionError::XtError(XtError::DuplicateVerdict) => {
            DisputesErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::XtError(XtError::JudgmentsNotSorted)
        | TransitionError::XtError(XtError::DuplicateJudgment) => {
            DisputesErrorCode::judgements_not_sorted_unique
        }
        TransitionError::XtError(XtError::CulpritsNotSorted)
        | TransitionError::XtError(XtError::DuplicateCulprit) => {
            DisputesErrorCode::culprits_not_sorted_unique
        }
        TransitionError::XtError(XtError::FaultsNotSorted)
        | TransitionError::XtError(XtError::DuplicateFault) => {
            DisputesErrorCode::faults_not_sorted_unique
        }
        TransitionError::XtError(XtError::InvalidJudgmentSignature(_))
        | TransitionError::XtError(XtError::InvalidCulpritSignature(_))
        | TransitionError::XtError(XtError::InvalidFaultSignature(_)) => {
            DisputesErrorCode::bad_signature
        }
        TransitionError::XtError(XtError::NotFault(_)) => DisputesErrorCode::fault_verdict_wrong,
        TransitionError::XtError(XtError::InvalidJudgmentsAge(_, _)) => {
            DisputesErrorCode::bad_judgement_age
        }
        TransitionError::XtError(XtError::NotEnoughCulprit(_)) => {
            DisputesErrorCode::not_enough_culprits
        }
        TransitionError::XtError(XtError::NotEnoughFault(_)) => {
            DisputesErrorCode::not_enough_faults
        }
        TransitionError::XtError(XtError::InvalidVotesCount(_)) => {
            DisputesErrorCode::bad_vote_split
        }
        TransitionError::XtError(XtError::InvalidCulpritReportHash(_)) => {
            DisputesErrorCode::culprits_verdict_not_bad
        }
        TransitionError::XtError(XtError::CulpritAlreadyReported(_))
        | TransitionError::XtError(XtError::FaultAlreadyReported(_)) => {
            DisputesErrorCode::offender_already_reported
        }
        TransitionError::XtError(XtError::InvalidCulpritsGuarantorKey(_)) => {
            DisputesErrorCode::bad_guarantor_key
        }
        TransitionError::XtError(XtError::InvalidFaultsAuditorKey(_)) => {
            DisputesErrorCode::bad_auditor_key
        }
        _ => DisputesErrorCode::reserved,
    }
}
