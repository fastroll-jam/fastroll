use crate::asn_types::reports::ReportsErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> ReportsErrorCode {
    match e {
        TransitionError::XtValidationError(XtError::InvalidCoreIndex) => {
            ReportsErrorCode::bad_core_index
        }
        TransitionError::XtValidationError(XtError::WorkReportTimeslotInFuture) => {
            ReportsErrorCode::future_report_slot
        }
        TransitionError::XtValidationError(XtError::WorkReportTimeslotTooOld) => {
            ReportsErrorCode::report_epoch_before_last
        }
        TransitionError::XtValidationError(XtError::InvalidGuarantorCount(_, _)) => {
            ReportsErrorCode::insufficient_guarantees
        }
        TransitionError::XtValidationError(XtError::DuplicateCoreIndex)
        | TransitionError::XtValidationError(XtError::GuaranteesNotSorted) => {
            ReportsErrorCode::out_of_order_guarantee
        }
        TransitionError::XtValidationError(XtError::DuplicateGuarantor)
        | TransitionError::XtValidationError(XtError::CredentialsNotSorted(_)) => {
            ReportsErrorCode::not_sorted_or_unique_guarantors
        }
        TransitionError::XtValidationError(XtError::GuarantorNotAssignedForCore(_, _, _)) => {
            ReportsErrorCode::wrong_assignment
        }
        TransitionError::XtValidationError(XtError::PendingReportExists(_)) => {
            ReportsErrorCode::core_engaged
        }
        TransitionError::XtValidationError(XtError::AnchorBlockNotFound(_, _)) => {
            ReportsErrorCode::anchor_not_recent
        }
        TransitionError::XtValidationError(XtError::AccountOfWorkDigestNotFound(_, _)) => {
            ReportsErrorCode::bad_service_id
        }
        TransitionError::XtValidationError(XtError::InvalidCodeHash(_, _, _)) => {
            ReportsErrorCode::bad_code_hash
        }
        TransitionError::XtValidationError(XtError::PrerequisiteNotFound(_, _)) => {
            ReportsErrorCode::dependency_missing
        }
        TransitionError::XtValidationError(XtError::DuplicateWorkPackageHash)
        | TransitionError::XtValidationError(XtError::WorkPackageAlreadyInHistory(_, _)) => {
            ReportsErrorCode::duplicate_package
        }
        TransitionError::XtValidationError(XtError::InvalidAnchorStateRoot(_, _)) => {
            ReportsErrorCode::bad_state_root
        }
        TransitionError::XtValidationError(XtError::InvalidAnchorBeefyRoot(_, _)) => {
            ReportsErrorCode::bad_beefy_mmr_root
        }
        TransitionError::XtValidationError(XtError::InvalidAuthorizerHash(_)) => {
            ReportsErrorCode::core_unauthorized
        }
        TransitionError::XtValidationError(XtError::InvalidValidatorIndex) => {
            ReportsErrorCode::bad_validator_index
        }
        TransitionError::XtValidationError(XtError::WorkReportTotalGasTooHigh) => {
            ReportsErrorCode::work_report_gas_too_high
        }
        TransitionError::XtValidationError(XtError::ServiceAccountGasLimitTooLow) => {
            ReportsErrorCode::service_item_gas_too_low
        }
        TransitionError::XtValidationError(XtError::TooManyDependencies(_)) => {
            ReportsErrorCode::too_many_dependencies
        }
        TransitionError::XtValidationError(XtError::SegmentsRootLookupEntryNotFound)
        | TransitionError::XtValidationError(XtError::SegmentsRoofLookupEntryInvalidValue) => {
            ReportsErrorCode::segment_root_lookup_invalid
        }
        TransitionError::XtValidationError(XtError::InvalidGuaranteesSignature(_)) => {
            ReportsErrorCode::bad_signature
        }
        TransitionError::XtValidationError(XtError::WorkReportOutputSizeLimitExceeded) => {
            ReportsErrorCode::work_report_too_big
        }
        _ => ReportsErrorCode::reserved,
    }
}
