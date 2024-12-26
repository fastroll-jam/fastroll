use crate::{
    utils::guarantor_rotation::GuarantorAssignment,
    validation::error::{ExtrinsicValidationError, ExtrinsicValidationError::*},
};
use rjam_common::{
    CoreIndex, Hash32, CORE_COUNT, GUARANTOR_ROTATION_PERIOD, MAX_LOOKUP_ANCHOR_AGE,
    PENDING_REPORT_TIMEOUT, X_G,
};
use rjam_crypto::verify_signature;
use rjam_state::StateManager;
use rjam_types::{
    common::workloads::{RefinementContext, WorkReport},
    extrinsics::guarantees::{GuaranteesCredential, GuaranteesExtrinsic, GuaranteesExtrinsicEntry},
    state::*,
};
use std::collections::HashSet;
// TODO: Add validation over gas allocation.

/// Validates contents of `GuaranteesExtrinsic` type.
///
/// # Validation Rules
///
/// ## Ordering
/// - Extrinsic entries must be ordered by the `work_report`'s `core_index` in ascending order.
///
/// ## Length Limit
/// - The length must not exceed `CORE_COUNT`.
///
/// ## Entry Validation
/// - `work_report`
///   - No duplicate `core_index` values are allowed within the extrinsic. Each core can only have
///     one work-report per extrinsic.
///   - A new work-report must not be introduced for a core if a previous work-report is still
///     pending on that core, unless the pending report has timed out.
///   - A new work-report must have its `authorizer_hash` present in the current authorizer pool
///     of the core on which the work is reported.
///   - No duplicate work-package hashes are allowed across different work reports within the extrinsic.
///   - The anchor block of each work-report must be within the last `H = 8` blocks, and its details
///     (header hash, state root, and Beefy root) must match those stored in the recent block history (`β`).
///   - The lookup-anchor block for each work-report must be within the last `L = 14,400` timeslots.
///     Additionally, the lookup-anchor's details (timeslot and header hash) must match those stored
///     in the ancestor header state.
///   - The work-package hash of each work-report must not match any work-package hashes from reports
///     already made in the past and thus should not be present in `β`.
///   - If the work-report depends on a prerequisite work-package, the prerequisite must either be
///     present in the current extrinsic or in the recent block history (`β`).
///   - All work results within each work-report must predict the correct code hash for the
///     corresponding service at the time of report submission.
/// - `credentials`
///   - The length of the `credentials` array for each work-report must be either 2 or 3
///     (representing the number of guarantors for the core).
///   - Entries in `credentials` must be sorted by the validator index in ascending order.
///   - Each credential's signature must be a valid Ed25519 signature of a message that consists of
///     the hash of the work-report, signed by the public key corresponding to the validator index.
///   - The validator who signs the credential must be assigned to the core in question, either in
///     the current guarantor assignment rotation or in the previous rotation.
pub struct GuaranteesExtrinsicValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> GuaranteesExtrinsicValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `GuaranteesExtrinsic`.
    pub fn validate(
        &self,
        extrinsic: &GuaranteesExtrinsic,
        header_timeslot_index: u32,
    ) -> Result<(), ExtrinsicValidationError> {
        // Check the length limit
        if extrinsic.len() > CORE_COUNT {
            return Err(GuaranteesEntryLimitExceeded(extrinsic.len(), CORE_COUNT));
        }

        // Check if the entries are sorted
        if !extrinsic.is_sorted() {
            return Err(GuaranteesNotSorted);
        }

        // Duplicate validation of core indices
        let mut work_report_cores = HashSet::new();
        let no_duplicate_cores = extrinsic
            .iter()
            .all(|entry| work_report_cores.insert(entry.work_report.core_index()));
        if !no_duplicate_cores {
            return Err(DuplicateCoreIndex);
        }

        // Duplicate validation of work packages
        let mut work_package_hashes = HashSet::new();
        let no_duplicate_packages = extrinsic
            .iter()
            .all(|entry| work_package_hashes.insert(entry.work_report.work_package_hash()));
        if !no_duplicate_packages {
            return Err(DuplicateWorkPackageHash);
        }

        // Additionally, check the cardinality of work package hashes and the work reports
        if work_package_hashes.len() != extrinsic.len() {
            return Err(DuplicateWorkPackageHash);
        }

        // Validate each entry
        let pending_reports = self.state_manager.get_pending_reports()?;
        let auth_pool = self.state_manager.get_auth_pool()?;
        let block_history = self.state_manager.get_block_history()?;

        for entry in extrinsic.iter() {
            self.validate_entry(
                entry,
                &pending_reports,
                &auth_pool,
                &block_history,
                &work_package_hashes,
                header_timeslot_index,
            )?;
        }

        Ok(())
    }

    /// Validates each `GuaranteesExtrinsicEntry`.
    pub fn validate_entry(
        &self,
        entry: &GuaranteesExtrinsicEntry,
        pending_reports: &PendingReports,
        auth_pool: &AuthPool,
        block_history: &BlockHistory,
        work_package_hashes: &HashSet<Hash32>,
        header_timeslot_index: u32,
    ) -> Result<(), ExtrinsicValidationError> {
        self.validate_work_report(
            &entry.work_report,
            pending_reports,
            auth_pool,
            block_history,
            work_package_hashes,
            header_timeslot_index,
        )?;

        self.validate_credentials(entry)?;

        Ok(())
    }

    fn validate_work_report(
        &self,
        work_report: &WorkReport,
        pending_reports: &PendingReports,
        auth_pool: &AuthPool,
        block_history: &BlockHistory,
        work_package_hashes: &HashSet<Hash32>,
        header_timeslot_index: u32,
    ) -> Result<(), ExtrinsicValidationError> {
        let core_index = work_report.core_index();
        let core_pending_report = pending_reports.get_by_core_index(core_index).clone();

        // Check if there is any work reported in this extrinsic while there is pending report
        // assigned to the core which is not timed-out.
        if let Some(core_report) = core_pending_report {
            let expiration = core_report.timeslot.slot() + PENDING_REPORT_TIMEOUT as u32;
            if header_timeslot_index < expiration {
                return Err(PendingReportExists(core_index));
            }
        }

        // Check the authorizer hash
        if !auth_pool
            .get_by_core_index(core_index)
            .contains(&work_report.authorizer_hash())
        {
            return Err(InvalidAuthorizerHash(core_index));
        }

        // Validate anchor block
        self.validate_anchor_block(core_index, work_report.refinement_context(), block_history)?;

        // Validate lookup-anchor block
        self.validate_lookup_anchor_block(
            core_index,
            work_report.refinement_context(),
            header_timeslot_index,
        )?;

        // Check that the work-package hash is not in the block history
        if block_history.check_work_package_hash_exists(&work_report.work_package_hash()) {
            return Err(WorkPackageAlreadyInHistory(
                core_index,
                work_report.work_package_hash().encode_hex(),
            ));
        }

        // Check prerequisite work-packages exist either in the current extrinsic or in the recent
        // block history
        for prerequisite_hash in work_report.prerequisite().iter() {
            if !work_package_hashes.contains(prerequisite_hash)
                && !block_history.check_work_package_hash_exists(prerequisite_hash)
            {
                return Err(PrerequisiteNotFound(
                    core_index,
                    prerequisite_hash.encode_hex(),
                ));
            }
        }

        // Validate work results' code hashes
        self.validate_work_results(work_report)?;

        Ok(())
    }

    fn validate_anchor_block(
        &self,
        core_index: CoreIndex,
        work_report_context: &RefinementContext,
        block_history: &BlockHistory,
    ) -> Result<(), ExtrinsicValidationError> {
        let anchor_hash = work_report_context.anchor_header_hash;
        let anchor_state_root = work_report_context.anchor_state_root;
        let anchor_beefy_root = work_report_context.beefy_root;

        // Check that the anchor block is within the last H blocks
        let anchor_in_block_history = block_history.get_by_header_hash(&anchor_hash);

        // Validate contents of the anchor block if it exists in the recent block history
        if let Some(entry) = anchor_in_block_history {
            if entry.state_root != anchor_state_root {
                return Err(InvalidAnchorStateRoot(core_index, anchor_hash.encode_hex()));
            }

            if entry.accumulation_result_mmr.super_peak()? != anchor_beefy_root {
                return Err(InvalidAnchorBeefyRoot(core_index, anchor_hash.encode_hex()));
            }
        } else {
            return Err(AnchorBlockNotFound(core_index, anchor_hash.encode_hex()));
        }

        Ok(())
    }

    fn validate_lookup_anchor_block(
        &self,
        core_index: CoreIndex,
        work_report_context: &RefinementContext,
        header_timeslot_index: u32,
    ) -> Result<(), ExtrinsicValidationError> {
        // TODO: Lookup recent `L` ancestor headers (eq.149 of v0.4.3) and check we have a record of the lookup anchor block.
        let lookup_anchor_hash = work_report_context.lookup_anchor_header_hash;
        let lookup_anchor_timeslot = work_report_context.lookup_anchor_timeslot;

        // Check that lookup-anchor block is within the last L timeslots
        if lookup_anchor_timeslot
            < header_timeslot_index.saturating_sub(MAX_LOOKUP_ANCHOR_AGE as u32)
        {
            return Err(LookupAnchorBlockTimeout(
                core_index,
                lookup_anchor_hash.encode_hex(),
            ));
        }

        Ok(())
    }

    fn validate_work_results(
        &self,
        work_report: &WorkReport,
    ) -> Result<(), ExtrinsicValidationError> {
        for result in work_report.results() {
            if let Some(expected_code_hash) = self
                .state_manager
                .get_account_code_hash(result.service_index)?
            {
                // code hash doesn't match
                if expected_code_hash != result.service_code_hash {
                    return Err(InvalidCodeHash(
                        work_report.core_index(),
                        result.service_index,
                        result.service_code_hash.encode_hex(),
                    ));
                }
            } else {
                // code hash doesn't exist for the service account
                return Err(CodeHashNotFound(
                    work_report.core_index(),
                    result.service_index,
                    result.service_code_hash.encode_hex(),
                ));
            }
        }

        Ok(())
    }

    fn validate_credentials(
        &self,
        entry: &GuaranteesExtrinsicEntry,
    ) -> Result<(), ExtrinsicValidationError> {
        let credentials = entry.credentials();
        // Check the length limit
        if !(credentials.len() == 2 || credentials.len() == 3) {
            return Err(InvalidGuarantorCount(
                credentials.len(),
                entry.work_report.core_index(),
            ));
        }

        // Check if the entries are sorted
        if !credentials.is_sorted() {
            return Err(CredentialsNotSorted(entry.work_report.core_index()));
        }

        // Duplicate validation of validator indices
        let mut validator_indices = HashSet::new();
        let no_duplicate_indices = credentials
            .iter()
            .all(|c| validator_indices.insert(c.validator_index));
        if !no_duplicate_indices {
            return Err(DuplicateGuarantor);
        }

        // Validate each credential
        for credential in credentials {
            self.validate_credential(&entry.work_report, entry.timeslot_index, credential)?;
        }

        Ok(())
    }

    fn validate_credential(
        &self,
        work_report: &WorkReport,
        entry_timeslot_index: u32,
        credential: &GuaranteesCredential,
    ) -> Result<(), ExtrinsicValidationError> {
        // Verify the signature
        let hash = work_report.hash()?;
        let mut message = Vec::with_capacity(X_G.len() + hash.len());
        message.extend_from_slice(X_G);
        message.extend_from_slice(hash.as_slice());

        // Get core indices and validator keys
        let current_timeslot = self.state_manager.get_timeslot()?.slot();
        let within_same_rotation = current_timeslot / GUARANTOR_ROTATION_PERIOD as u32
            == entry_timeslot_index / GUARANTOR_ROTATION_PERIOD as u32;

        let guarantor_assignment = if within_same_rotation {
            GuarantorAssignment::current_guarantor_assignments(self.state_manager)?
        } else {
            GuarantorAssignment::previous_guarantor_assignments(self.state_manager)?
        };

        let guarantor_public_key = get_validator_ed25519_key_by_index(
            &guarantor_assignment.validator_keys,
            credential.validator_index,
        );

        if !verify_signature(&message, &guarantor_public_key, &credential.signature) {
            return Err(InvalidGuaranteesSignature(credential.validator_index));
        }

        // Verify if the guarantor is assigned to the core index specified in the work report
        let assigned_core = guarantor_assignment.core_indices[credential.validator_index as usize];
        if assigned_core != work_report.core_index {
            return Err(GuarantorNotAssignedForCore(
                credential.validator_index,
                assigned_core,
                work_report.core_index,
            ));
        }

        // Verify the timeslot of the work report is within a valid range (not older than the previous guarantor rotation)
        if entry_timeslot_index > current_timeslot
            || entry_timeslot_index
                < GUARANTOR_ROTATION_PERIOD as u32
                    * ((current_timeslot / GUARANTOR_ROTATION_PERIOD as u32) - 1)
        {
            return Err(InvalidWorkReportTimeslot);
        }

        Ok(())
    }
}
