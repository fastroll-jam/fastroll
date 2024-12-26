use crate::state_transition::reports::asn_types::ReportsErrorCode;
use rjam_extrinsics::validation::error::ExtrinsicValidationError::*;
use rjam_transition::error::TransitionError;

/// Converts RJAM error types into test vector error code output
pub(crate) fn map_error_to_custom_code(e: TransitionError) -> ReportsErrorCode {
    match e {
        TransitionError::ExtrinsicValidationError(DuplicateCoreIndex) => {
            ReportsErrorCode::bad_core_index
        }
        TransitionError::ExtrinsicValidationError(InvalidGuarantorCount(_, _)) => {
            ReportsErrorCode::insufficient_guarantees
        }
        TransitionError::ExtrinsicValidationError(GuaranteesNotSorted) => {
            ReportsErrorCode::out_of_order_guarantee
        }
        TransitionError::ExtrinsicValidationError(DuplicateGuarantor)
        | TransitionError::ExtrinsicValidationError(CredentialsNotSorted(_)) => {
            ReportsErrorCode::not_sorted_or_unique_guarantors
        }
        TransitionError::ExtrinsicValidationError(GuarantorNotAssignedForCore(_, _, _)) => {
            ReportsErrorCode::wrong_assignment
        }
        TransitionError::ExtrinsicValidationError(AnchorBlockNotFound(_, _)) => {
            ReportsErrorCode::anchor_not_recent
        }
        TransitionError::ExtrinsicValidationError(InvalidCodeHash(_, _, _))
        | TransitionError::ExtrinsicValidationError(CodeHashNotFound(_, _, _)) => {
            ReportsErrorCode::bad_code_hash
        }
        TransitionError::ExtrinsicValidationError(PrerequisiteNotFound(_, _)) => {
            ReportsErrorCode::dependency_missing
        }
        TransitionError::ExtrinsicValidationError(DuplicateWorkPackageHash)
        | TransitionError::ExtrinsicValidationError(WorkPackageAlreadyInHistory(_, _)) => {
            ReportsErrorCode::duplicate_package
        }
        TransitionError::ExtrinsicValidationError(InvalidAnchorStateRoot(_, _)) => {
            ReportsErrorCode::bad_state_root
        }
        TransitionError::ExtrinsicValidationError(InvalidAnchorBeefyRoot(_, _)) => {
            ReportsErrorCode::bad_beefy_mmr_root
        }
        TransitionError::ExtrinsicValidationError(InvalidAuthorizerHash(_)) => {
            ReportsErrorCode::core_unauthorized
        }
        TransitionError::ExtrinsicValidationError(InvalidGuaranteesSignature(_)) => {
            ReportsErrorCode::bad_signature
        }

        _ => ReportsErrorCode::reserved,
    }
}
