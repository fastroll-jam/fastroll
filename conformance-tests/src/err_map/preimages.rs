use crate::asn_types::preimages::PreimagesErrorCode;
use rjam_extrinsics::validation::error::XtValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> PreimagesErrorCode {
    match e {
        TransitionError::XtValidationError(PreimageLookupsNotSorted)
        | TransitionError::XtValidationError(DuplicatePreimageLookup) => {
            PreimagesErrorCode::preimages_not_sorted_unique
        }
        TransitionError::XtValidationError(PreimageAlreadyIntegrated(_))
        | TransitionError::XtValidationError(PreimageNotSolicited(_)) => {
            PreimagesErrorCode::preimage_unneeded
        }
        _ => PreimagesErrorCode::reserved,
    }
}
