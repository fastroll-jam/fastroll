use crate::disputes::asn_types::ErrorCode;
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;

// TODO: complete error mapping
/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> ErrorCode {
    println!(">>> ERROR type: {:?}", e);
    match e {
        TransitionError::ExtrinsicValidationError(VerdictAlreadyExists) => {
            ErrorCode::already_judged
        }
        TransitionError::ExtrinsicValidationError(VerdictsNotSorted) => {
            ErrorCode::verdicts_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(JudgmentsNotSorted) => {
            ErrorCode::judgements_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(CulpritsNotSorted) => {
            ErrorCode::culprits_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(FaultsNotSorted) => {
            ErrorCode::faults_not_sorted_unique
        }
        TransitionError::ExtrinsicValidationError(InvalidJudgmentSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidCulpritSignature(_))
        | TransitionError::ExtrinsicValidationError(InvalidFaultSignature(_)) => {
            ErrorCode::bad_signature
        }
        _ => ErrorCode::reserved,
    }
}
