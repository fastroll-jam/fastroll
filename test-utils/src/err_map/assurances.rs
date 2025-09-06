use fr_asn_types::assurances::AssurancesErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> AssurancesErrorCode {
    match e {
        TransitionError::XtError(XtError::InvalidAssuranceParentHash(_, _, _)) => {
            AssurancesErrorCode::bad_attestation_parent
        }
        TransitionError::XtError(XtError::InvalidValidatorIndex) => {
            AssurancesErrorCode::bad_validator_index
        }
        TransitionError::XtError(XtError::NoPendingReportForCore(_, _)) => {
            AssurancesErrorCode::core_not_engaged
        }
        TransitionError::XtError(XtError::InvalidAssuranceSignature(_)) => {
            AssurancesErrorCode::bad_signature
        }
        TransitionError::XtError(XtError::AssurancesNotSorted)
        | TransitionError::XtError(XtError::DuplicateAssurer) => {
            AssurancesErrorCode::not_sorted_or_unique_assurers
        }
        _ => AssurancesErrorCode::reserved,
    }
}
