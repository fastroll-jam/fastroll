use crate::state_transition::reports::asn_types::ReportsErrorCode;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> ReportsErrorCode {
    // TODO: impl
    match e {
        _ => ReportsErrorCode::bad_code_hash,
    }
}
