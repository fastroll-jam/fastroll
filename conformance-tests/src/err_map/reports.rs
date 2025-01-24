use crate::asn_types::reports::ReportsErrorCode;
use rjam_extrinsics::validation::error::XtValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> ReportsErrorCode {
    match e {
        TransitionError::XtValidationError(InvalidCoreIndex) => ReportsErrorCode::bad_core_index,
        TransitionError::XtValidationError(WorkReportTimeslotInFuture) => {
            ReportsErrorCode::future_report_slot
        }
        TransitionError::XtValidationError(WorkReportTimeslotTooOld) => {
            ReportsErrorCode::report_epoch_before_last
        }
        TransitionError::XtValidationError(InvalidGuarantorCount(_, _)) => {
            ReportsErrorCode::insufficient_guarantees
        }
        TransitionError::XtValidationError(DuplicateCoreIndex)
        | TransitionError::XtValidationError(GuaranteesNotSorted) => {
            ReportsErrorCode::out_of_order_guarantee
        }
        TransitionError::XtValidationError(DuplicateGuarantor)
        | TransitionError::XtValidationError(CredentialsNotSorted(_)) => {
            ReportsErrorCode::not_sorted_or_unique_guarantors
        }
        TransitionError::XtValidationError(GuarantorNotAssignedForCore(_, _, _)) => {
            ReportsErrorCode::wrong_assignment
        }
        TransitionError::XtValidationError(PendingReportExists(_)) => {
            ReportsErrorCode::core_engaged
        }
        TransitionError::XtValidationError(AnchorBlockNotFound(_, _)) => {
            ReportsErrorCode::anchor_not_recent
        }
        TransitionError::XtValidationError(AccountOfWorkResultNotFound(_, _)) => {
            ReportsErrorCode::bad_service_id
        }
        TransitionError::XtValidationError(InvalidCodeHash(_, _, _)) => {
            ReportsErrorCode::bad_code_hash
        }
        TransitionError::XtValidationError(PrerequisiteNotFound(_, _)) => {
            ReportsErrorCode::dependency_missing
        }
        TransitionError::XtValidationError(DuplicateWorkPackageHash)
        | TransitionError::XtValidationError(WorkPackageAlreadyInHistory(_, _)) => {
            ReportsErrorCode::duplicate_package
        }
        TransitionError::XtValidationError(InvalidAnchorStateRoot(_, _)) => {
            ReportsErrorCode::bad_state_root
        }
        TransitionError::XtValidationError(InvalidAnchorBeefyRoot(_, _)) => {
            ReportsErrorCode::bad_beefy_mmr_root
        }
        TransitionError::XtValidationError(InvalidAuthorizerHash(_)) => {
            ReportsErrorCode::core_unauthorized
        }
        TransitionError::XtValidationError(InvalidValidatorIndex) => {
            ReportsErrorCode::bad_validator_index
        }
        TransitionError::XtValidationError(WorkReportTotalGasTooHigh) => {
            ReportsErrorCode::work_report_gas_too_high
        }
        TransitionError::XtValidationError(ServiceAccountGasLimitTooLow) => {
            ReportsErrorCode::service_item_gas_too_low
        }
        TransitionError::XtValidationError(TooManyDependencies(_)) => {
            ReportsErrorCode::too_many_dependencies
        }
        TransitionError::XtValidationError(SegmentsRootLookupEntryNotFound)
        | TransitionError::XtValidationError(SegmentsRoofLookupEntryInvalidValue) => {
            ReportsErrorCode::segment_root_lookup_invalid
        }
        TransitionError::XtValidationError(InvalidGuaranteesSignature(_)) => {
            ReportsErrorCode::bad_signature
        }
        TransitionError::XtValidationError(WorkReportOutputSizeLimitExceeded) => {
            ReportsErrorCode::work_report_too_big
        }
        _ => ReportsErrorCode::reserved,
    }
}
