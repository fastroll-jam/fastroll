use fr_asn_types::types::preimages::PreimagesErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> PreimagesErrorCode {
    match e {
        TransitionError::XtError(XtError::PreimageLookupsNotSorted)
        | TransitionError::XtError(XtError::DuplicatePreimageLookup) => {
            PreimagesErrorCode::preimages_not_sorted_unique
        }
        TransitionError::XtError(XtError::PreimageAlreadyIntegrated(_))
        | TransitionError::XtError(XtError::PreimageNotSolicited(_)) => {
            PreimagesErrorCode::preimage_unneeded
        }
        _ => PreimagesErrorCode::reserved,
    }
}
