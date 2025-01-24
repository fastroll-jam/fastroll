use crate::asn_types::assurances::AssurancesErrorCode;
use rjam_extrinsics::validation::error::XtValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> AssurancesErrorCode {
    match e {
        TransitionError::XtValidationError(InvalidAssuranceParentHash(_, _, _)) => {
            AssurancesErrorCode::bad_attestation_parent
        }
        TransitionError::XtValidationError(InvalidValidatorIndex) => {
            AssurancesErrorCode::bad_validator_index
        }
        TransitionError::XtValidationError(NoPendingReportForCore(_, _)) => {
            AssurancesErrorCode::core_not_engaged
        }
        TransitionError::XtValidationError(InvalidAssuranceSignature(_)) => {
            AssurancesErrorCode::bad_signature
        }
        TransitionError::XtValidationError(AssurancesNotSorted)
        | TransitionError::XtValidationError(DuplicateAssurer) => {
            AssurancesErrorCode::not_sorted_or_unique_assurers
        }
        _ => AssurancesErrorCode::reserved,
    }
}
