use crate::asn_types::assurances::AssurancesErrorCode;
use rjam_extrinsics::validation::error::XtError;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> AssurancesErrorCode {
    match e {
        TransitionError::XtValidationError(XtError::InvalidAssuranceParentHash(_, _, _)) => {
            AssurancesErrorCode::bad_attestation_parent
        }
        TransitionError::XtValidationError(XtError::InvalidValidatorIndex) => {
            AssurancesErrorCode::bad_validator_index
        }
        TransitionError::XtValidationError(XtError::NoPendingReportForCore(_, _)) => {
            AssurancesErrorCode::core_not_engaged
        }
        TransitionError::XtValidationError(XtError::InvalidAssuranceSignature(_)) => {
            AssurancesErrorCode::bad_signature
        }
        TransitionError::XtValidationError(XtError::AssurancesNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicateAssurer) => {
            AssurancesErrorCode::not_sorted_or_unique_assurers
        }
        _ => AssurancesErrorCode::reserved,
    }
}
