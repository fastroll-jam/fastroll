use crate::{
    utils::guarantor_rotation::GuarantorAssignment,
    validation::error::{XtValidationError, XtValidationError::*},
};
use rjam_common::{
    CoreIndex, Ed25519PubKey, Hash32, ACCUMULATION_GAS_PER_CORE, CORE_COUNT,
    GUARANTOR_ROTATION_PERIOD, MAX_LOOKUP_ANCHOR_AGE, MAX_REPORT_DEPENDENCIES,
    PENDING_REPORT_TIMEOUT, WORK_REPORT_OUTPUT_SIZE_LIMIT, X_G,
};
use rjam_crypto::verify_signature;
use rjam_state::StateManager;
use rjam_types::{
    common::workloads::{RefinementContext, WorkReport},
    extrinsics::guarantees::{GuaranteesCredential, GuaranteesXt, GuaranteesXtEntry},
    state::*,
};
use std::collections::HashSet;
// TODO: Add validation over gas allocation.

/// Validates contents of `GuaranteesXt` type.
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
pub struct GuaranteesXtValidator<'a> {
    state_manager: &'a StateManager,
}

impl<'a> GuaranteesXtValidator<'a> {
    pub fn new(state_manager: &'a StateManager) -> Self {
        Self { state_manager }
    }

    /// Validates the entire `GuaranteesXt`.
    ///
    /// Returns `Ed25519PubKey`s of guarantors of all report entries.
    pub async fn validate(
        &self,
        extrinsic: &GuaranteesXt,
        header_timeslot_index: u32,
    ) -> Result<Vec<Ed25519PubKey>, XtValidationError> {
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

        // Extract exports manifests from the guarantee extrinsics
        let exports_manifests: Vec<ReportedWorkPackage> = extrinsic
            .iter()
            .map(|e| e.work_report.extract_exports_manifest())
            .collect();

        // Validate each entry
        let pending_reports = self.state_manager.get_pending_reports().await?;
        let auth_pool = self.state_manager.get_auth_pool().await?;
        let block_history = self.state_manager.get_block_history().await?;

        let mut all_guarantor_keys = vec![];
        for entry in extrinsic.iter() {
            let guarantor_keys = self
                .validate_entry(
                    entry,
                    &exports_manifests,
                    &pending_reports,
                    &auth_pool,
                    &block_history,
                    &work_package_hashes,
                    header_timeslot_index,
                )
                .await?;
            all_guarantor_keys.extend(guarantor_keys);
        }

        Ok(all_guarantor_keys)
    }

    /// Validates each `GuaranteesXtEntry`.
    ///
    /// Returns `Ed25519PubKey`s of guarantors of the report entry.
    #[allow(clippy::too_many_arguments)]
    async fn validate_entry(
        &self,
        entry: &GuaranteesXtEntry,
        exports_manifests: &[ReportedWorkPackage],
        pending_reports: &PendingReports,
        auth_pool: &AuthPool,
        block_history: &BlockHistory,
        work_package_hashes: &HashSet<Hash32>,
        header_timeslot_index: u32,
    ) -> Result<Vec<Ed25519PubKey>, XtValidationError> {
        self.validate_work_report(
            &entry.work_report,
            exports_manifests,
            pending_reports,
            auth_pool,
            block_history,
            work_package_hashes,
            header_timeslot_index,
        )
        .await?;

        self.validate_credentials(entry).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn validate_work_report(
        &self,
        work_report: &WorkReport,
        exports_manifests: &[ReportedWorkPackage],
        pending_reports: &PendingReports,
        auth_pool: &AuthPool,
        block_history: &BlockHistory,
        work_package_hashes: &HashSet<Hash32>,
        header_timeslot_index: u32,
    ) -> Result<(), XtValidationError> {
        // Check work report output size limit
        if work_report.total_output_size() > WORK_REPORT_OUTPUT_SIZE_LIMIT {
            return Err(WorkReportOutputSizeLimitExceeded);
        }

        // Check gas limit of the work report
        if work_report.total_accumulation_gas_allotted() > ACCUMULATION_GAS_PER_CORE {
            return Err(WorkReportTotalGasTooHigh);
        }
        for result_item in &work_report.results {
            // TODO: error handling for target account being not found?
            let target_service_account_metadata = self
                .state_manager
                .get_account_metadata(result_item.service_id)
                .await?;

            let target_service_account_min_item_gas = match target_service_account_metadata {
                Some(account) => account.gas_limit_accumulate,
                None => continue,
            };

            if result_item.gas_prioritization_ratio < target_service_account_min_item_gas {
                return Err(ServiceAccountGasLimitTooLow);
            }
        }

        let core_index = work_report.core_index();
        let core_pending_report = pending_reports
            .get_by_core_index(core_index)
            .map_err(|_| InvalidCoreIndex)?;

        // Check if there is any work reported in this extrinsic while there is pending report
        // assigned to the core which is not timed-out.
        if let Some(core_report) = core_pending_report {
            let expiration = core_report.reported_timeslot.slot() + PENDING_REPORT_TIMEOUT as u32;
            if header_timeslot_index < expiration {
                return Err(PendingReportExists(core_index));
            }
        }

        // Check the authorizer hash
        if !auth_pool
            .get_by_core_index(core_index)
            .map_err(|_| InvalidCoreIndex)?
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

        // Check the dependency items limit. Sum of the number of segment-root lookup dictionary items
        // and the number of prerequisites must not exceed `MAX_REPORT_DEPENDENCIES`
        let prerequisites_count = work_report
            .refinement_context()
            .prerequisite_work_packages
            .len();
        let segment_root_lookup_entries_count = work_report.segment_roots_lookup().len();
        if prerequisites_count + segment_root_lookup_entries_count > MAX_REPORT_DEPENDENCIES {
            return Err(TooManyDependencies(core_index));
        }

        // Check the segment root lookup dictionary entries can be found either in the same extrinsic
        // or in the block history
        let mut exports_manifests_merged = block_history.get_reported_packages_flattened();
        exports_manifests_merged.extend_from_slice(exports_manifests);

        for (package_hash, segments_root) in work_report.segment_roots_lookup() {
            if let Some(observed_segment_root) = Self::find_segments_root_from_work_package_hash(
                &exports_manifests_merged,
                package_hash,
            ) {
                if &observed_segment_root != segments_root {
                    return Err(SegmentsRoofLookupEntryInvalidValue);
                }
            } else {
                return Err(SegmentsRootLookupEntryNotFound);
            }
        }

        // Check prerequisite work-packages exist either in the current extrinsic or in the recent
        // block history
        for prerequisite_hash in work_report.prerequisites().iter() {
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
        self.validate_work_results(work_report).await?;

        Ok(())
    }

    /// Helper method to find segments root by work package hash from a vector of `ReportedWorkPackage` type.
    ///
    /// A vector of flattened `ReportedWorkPackage`s found from the recent block history
    /// and the same guarantees extrinsic should be provided as the argument `reported_packages`.
    fn find_segments_root_from_work_package_hash(
        reported_packages: &[ReportedWorkPackage],
        work_package_hash: &Hash32,
    ) -> Option<Hash32> {
        let reported_package = reported_packages
            .iter()
            .find(|r| r.work_package_hash == *work_package_hash);

        reported_package.map(|r| r.segment_root)
    }

    fn validate_anchor_block(
        &self,
        core_index: CoreIndex,
        work_report_context: &RefinementContext,
        block_history: &BlockHistory,
    ) -> Result<(), XtValidationError> {
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
    ) -> Result<(), XtValidationError> {
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

    async fn validate_work_results(
        &self,
        work_report: &WorkReport,
    ) -> Result<(), XtValidationError> {
        for result in work_report.results() {
            if let Some(expected_code_hash) = self
                .state_manager
                .get_account_code_hash(result.service_id)
                .await?
            {
                // code hash doesn't match
                if expected_code_hash != result.service_code_hash {
                    return Err(InvalidCodeHash(
                        work_report.core_index(),
                        result.service_id,
                        result.service_code_hash.encode_hex(),
                    ));
                }
            } else {
                // service account not found
                return Err(AccountOfWorkResultNotFound(
                    work_report.core_index(),
                    result.service_id,
                ));
            }
        }

        Ok(())
    }

    async fn validate_credentials(
        &self,
        entry: &GuaranteesXtEntry,
    ) -> Result<Vec<Ed25519PubKey>, XtValidationError> {
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
        let mut guarantor_keys = Vec::with_capacity(credentials.len());
        for credential in credentials {
            let guarantor = self
                .validate_credential(&entry.work_report, entry.timeslot_index, credential)
                .await?;
            guarantor_keys.push(guarantor);
        }

        Ok(guarantor_keys)
    }

    async fn validate_credential(
        &self,
        work_report: &WorkReport,
        entry_timeslot_index: u32,
        credential: &GuaranteesCredential,
    ) -> Result<Ed25519PubKey, XtValidationError> {
        // Verify the signature
        let hash = work_report.hash()?;
        let mut message = Vec::with_capacity(X_G.len() + hash.len());
        message.extend_from_slice(X_G);
        message.extend_from_slice(hash.as_slice());

        // Get core indices and validator keys
        let current_timeslot_index = self.state_manager.get_timeslot().await?.slot();
        let guarantor_assignment = self
            .get_guarantor_assignment(entry_timeslot_index, current_timeslot_index)
            .await?;
        let guarantor_public_key = get_validator_ed25519_key_by_index(
            &guarantor_assignment.validator_keys,
            credential.validator_index,
        )
        .map_err(|_| InvalidValidatorIndex)?;

        if !verify_signature(&message, &guarantor_public_key, &credential.signature) {
            return Err(InvalidGuaranteesSignature(credential.validator_index));
        }

        // Verify the timeslot of the work report is within a valid range (not in the future)
        if entry_timeslot_index > current_timeslot_index {
            return Err(WorkReportTimeslotInFuture);
        }

        // Verify the timeslot of the work report is within a valid range (not older than the previous guarantor rotation)
        if entry_timeslot_index
            < GUARANTOR_ROTATION_PERIOD as u32
                * ((current_timeslot_index / GUARANTOR_ROTATION_PERIOD as u32) - 1)
        {
            return Err(WorkReportTimeslotTooOld);
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

        Ok(guarantor_public_key)
    }

    pub async fn get_guarantor_assignment(
        &self,
        entry_timeslot_index: u32,
        current_timeslot_index: u32,
    ) -> Result<GuarantorAssignment, XtValidationError> {
        let within_same_rotation = current_timeslot_index / GUARANTOR_ROTATION_PERIOD as u32
            == entry_timeslot_index / GUARANTOR_ROTATION_PERIOD as u32;
        if within_same_rotation {
            Ok(GuarantorAssignment::current_guarantor_assignments(self.state_manager).await?)
        } else {
            Ok(GuarantorAssignment::previous_guarantor_assignments(self.state_manager).await?)
        }
    }
}
