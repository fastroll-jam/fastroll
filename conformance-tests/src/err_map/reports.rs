use fr_asn_types::types::reports::ReportsErrorCode;
use fr_extrinsics::validation::error::XtError;
use fr_transition::error::TransitionError;

/// Converts FastRoll error types into test vector error code output
pub fn map_error_to_custom_code(e: TransitionError) -> ReportsErrorCode {
    match e {
        TransitionError::XtError(XtError::InvalidCoreIndex) => ReportsErrorCode::bad_core_index,
        TransitionError::XtError(XtError::WorkReportTimeslotInFuture) => {
            ReportsErrorCode::future_report_slot
        }
        TransitionError::XtError(XtError::WorkReportTimeslotTooOld) => {
            ReportsErrorCode::report_epoch_before_last
        }
        TransitionError::XtError(XtError::InvalidGuarantorCount(_, _)) => {
            ReportsErrorCode::insufficient_guarantees
        }
        TransitionError::XtError(XtError::DuplicateCoreIndex)
        | TransitionError::XtError(XtError::GuaranteesNotSorted) => {
            ReportsErrorCode::out_of_order_guarantee
        }
        TransitionError::XtError(XtError::DuplicateGuarantor)
        | TransitionError::XtError(XtError::CredentialsNotSorted(_)) => {
            ReportsErrorCode::not_sorted_or_unique_guarantors
        }
        TransitionError::XtError(XtError::GuarantorNotAssignedForCore(_, _, _)) => {
            ReportsErrorCode::wrong_assignment
        }
        TransitionError::XtError(XtError::PendingReportExists(_)) => ReportsErrorCode::core_engaged,
        TransitionError::XtError(XtError::AnchorBlockNotFound(_, _)) => {
            ReportsErrorCode::anchor_not_recent
        }
        TransitionError::XtError(XtError::AccountOfWorkDigestNotFound(_, _)) => {
            ReportsErrorCode::bad_service_id
        }
        TransitionError::XtError(XtError::InvalidCodeHash(_, _, _)) => {
            ReportsErrorCode::bad_code_hash
        }
        TransitionError::XtError(XtError::PrerequisiteNotFound(_, _)) => {
            ReportsErrorCode::dependency_missing
        }
        TransitionError::XtError(XtError::DuplicateWorkPackageHash)
        | TransitionError::XtError(XtError::WorkPackageAlreadyInHistory(_, _)) => {
            ReportsErrorCode::duplicate_package
        }
        TransitionError::XtError(XtError::InvalidAnchorStateRoot(_, _)) => {
            ReportsErrorCode::bad_state_root
        }
        TransitionError::XtError(XtError::InvalidAnchorBeefyRoot(_, _)) => {
            ReportsErrorCode::bad_beefy_mmr_root
        }
        TransitionError::XtError(XtError::InvalidAuthorizerHash(_)) => {
            ReportsErrorCode::core_unauthorized
        }
        TransitionError::XtError(XtError::InvalidValidatorIndex) => {
            ReportsErrorCode::bad_validator_index
        }
        TransitionError::XtError(XtError::WorkReportTotalGasTooHigh) => {
            ReportsErrorCode::work_report_gas_too_high
        }
        TransitionError::XtError(XtError::ServiceAccountGasLimitTooLow) => {
            ReportsErrorCode::service_item_gas_too_low
        }
        TransitionError::XtError(XtError::TooManyDependencies(_)) => {
            ReportsErrorCode::too_many_dependencies
        }
        TransitionError::XtError(XtError::SegmentsRootLookupEntryNotFound)
        | TransitionError::XtError(XtError::SegmentsRoofLookupEntryInvalidValue) => {
            ReportsErrorCode::segment_root_lookup_invalid
        }
        TransitionError::XtError(XtError::InvalidGuaranteesSignature(_)) => {
            ReportsErrorCode::bad_signature
        }
        TransitionError::XtError(XtError::WorkReportOutputSizeLimitExceeded) => {
            ReportsErrorCode::work_report_too_big
        }
        _ => ReportsErrorCode::reserved,
    }
}
