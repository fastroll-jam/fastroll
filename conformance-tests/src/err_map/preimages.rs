use crate::asn_types::preimages::PreimagesErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> PreimagesErrorCode {
    match e {
        TransitionError::XtValidationError(XtError::PreimageLookupsNotSorted)
        | TransitionError::XtValidationError(XtError::DuplicatePreimageLookup) => {
            PreimagesErrorCode::preimages_not_sorted_unique
        }
        TransitionError::XtValidationError(XtError::PreimageAlreadyIntegrated(_))
        | TransitionError::XtValidationError(XtError::PreimageNotSolicited(_)) => {
            PreimagesErrorCode::preimage_unneeded
        }
        _ => PreimagesErrorCode::reserved,
    }
}
