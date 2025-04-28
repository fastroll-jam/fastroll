use crate::utils::spawn_timed;
use rjam_block::types::{
    block::{Block, BlockHeaderError, VrfSig},
    extrinsics::disputes::OffendersHeaderMarker,
};
use rjam_common::{workloads::ReportedWorkPackage, Hash32};
use rjam_crypto::traits::VrfSignature;
use rjam_pvm_invocation::pipeline::{
    accumulate_result_commitment, utils::collect_accumulatable_reports,
};
use rjam_state::{error::StateManagerError, manager::StateManager, types::Timeslot};
use rjam_transition::{
    error::TransitionError,
    procedures::chain_extension::{mark_safrole_header_markers, SafroleHeaderMarkers},
    state::{
        accumulate::{transition_accumulate_history, transition_accumulate_queue},
        authorizer::transition_auth_pool,
        disputes::transition_disputes,
        entropy::{transition_epoch_entropy_on_epoch_change, transition_epoch_entropy_per_block},
        history::{transition_block_history_append, transition_block_history_parent_root},
        reports::{
            transition_reports_clear_availables, transition_reports_eliminate_invalid,
            transition_reports_update_entries,
        },
        safrole::transition_safrole,
        services::transition_on_accumulate,
        statistics::transition_onchain_statistics,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
use std::sync::Arc;
use thiserror::Error;
use tokio::try_join;

#[derive(Debug, Error)]
pub enum BlockExecutionError {
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("TransitionError: {0}")]
    TransitionError(#[from] TransitionError),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct BlockExecutionOutput {
    pub offenders_marker: OffendersHeaderMarker,
    pub safrole_markers: SafroleHeaderMarkers,
    pub accumulate_root: Hash32,
    pub reported_packages: Vec<ReportedWorkPackage>,
}

pub struct BlockExecutor {
    state_manager: Arc<StateManager>,
}

impl BlockExecutor {
    pub fn new(state_manager: Arc<StateManager>) -> Self {
        Self { state_manager }
    }

    // TODO: Split this more so that header could be finalized earlier with necessary STFs run first.
    pub async fn run_state_transition(
        &self,
        block: &Block,
    ) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let xt_cloned = block.extrinsics.clone();
        let disputes_xt = block.extrinsics.disputes.clone();
        let assurances_xt = block.extrinsics.assurances.clone();
        let guarantees_xt = block.extrinsics.guarantees.clone();
        let tickets_xt = block.extrinsics.tickets.clone();
        let prev_timeslot = self.state_manager.get_timeslot().await?;
        let header_timeslot = Timeslot::new(block.header.timeslot_index());
        let parent_hash = block.header.header_data.parent_hash.clone();
        let parent_state_root = block.header.header_data.parent_state_root.clone();
        let author_index = block.header.header_data.author_index;

        // Timeslot STF
        let manager = self.state_manager.clone();
        spawn_timed("timeslot stf", async move {
            transition_timeslot(manager, &header_timeslot).await
        })
        .await??;

        // Epoch progress check
        let curr_timeslot = self.state_manager.get_timeslot().await?;
        let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

        // --- Spawn STF tasks

        // Disputes STF
        let manager = self.state_manager.clone();
        let disputes_xt_cloned = disputes_xt.clone();
        let disputes_jh = spawn_timed("disputes_jh", async move {
            transition_disputes(manager, &disputes_xt_cloned, prev_timeslot).await
        });

        // Entropy STF (on-epoch-change transition only)
        let manager = self.state_manager.clone();
        let entropy_jh = spawn_timed("entropy_jh", async move {
            transition_epoch_entropy_on_epoch_change(manager, epoch_progressed).await
        });

        // PastSet STF
        let manager = self.state_manager.clone();
        let past_set_jh = spawn_timed("pastset_jh", async move {
            transition_past_set(manager, epoch_progressed).await
        });

        // ActiveSet STF
        let manager = self.state_manager.clone();
        let active_set_jh = spawn_timed("active_set_jh", async move {
            transition_active_set(manager, epoch_progressed).await
        });

        // Reports STF
        // TODO: remove `unwrap`s
        let manager = self.state_manager.clone();
        let disputes_xt_cloned = disputes_xt.clone();
        let guarantees_xt_cloned = guarantees_xt.clone();
        let reports_jh = spawn_timed("reports_jh", async move {
            transition_reports_eliminate_invalid(
                manager.clone(),
                &disputes_xt_cloned,
                prev_timeslot,
            )
            .await
            .unwrap();
            let available_reports =
                transition_reports_clear_availables(manager.clone(), &assurances_xt, parent_hash)
                    .await
                    .unwrap();
            let (reported, _reporters) =
                transition_reports_update_entries(manager, &guarantees_xt_cloned, curr_timeslot)
                    .await
                    .unwrap();
            (available_reports, reported)
        });

        // Authorizer STF
        let manager = self.state_manager.clone();
        let auth_pool_jh = spawn_timed("auth_pool_jh", async move {
            transition_auth_pool(manager, &guarantees_xt, header_timeslot).await
        });

        // --- Join: Disputes, Entropy, PastSet, ActiveSet STFs (dependencies for Safrole STF)
        #[allow(unused_must_use)]
        try_join!(disputes_jh, entropy_jh, past_set_jh, active_set_jh)?;

        // Safrole STF
        let manager = self.state_manager.clone();
        let safrole_jh = spawn_timed("safrole_jh", async move {
            transition_safrole(
                manager,
                &prev_timeslot,
                &curr_timeslot,
                epoch_progressed,
                &tickets_xt,
            )
            .await
        });

        // OnChainStatistics STF
        let manager = self.state_manager.clone();
        let stats_jh = spawn_timed("stats_jh", async move {
            transition_onchain_statistics(manager, epoch_progressed, author_index, &xt_cloned).await
        });

        // Accumulate STF
        let (available_reports, reported_packages) = reports_jh.await?;
        let acc_queue = self.state_manager.get_accumulate_queue().await?;
        let acc_history = self.state_manager.get_accumulate_history().await?;
        let (accumulatable_reports, queued_reports) = collect_accumulatable_reports(
            available_reports,
            &acc_queue,
            &acc_history,
            prev_timeslot.slot(),
        );
        let manager = self.state_manager.clone();
        let acc_jh = spawn_timed("acc_jh", async move {
            let acc_summary = transition_on_accumulate(manager.clone(), &accumulatable_reports)
                .await
                .unwrap();
            transition_accumulate_history(
                manager.clone(),
                &accumulatable_reports,
                acc_summary.accumulated_reports_count,
            )
            .await
            .unwrap();
            transition_accumulate_queue(manager, &queued_reports, prev_timeslot, curr_timeslot)
                .await
                .unwrap();
            accumulate_result_commitment(acc_summary.output_pairs)
        });

        // Join remaining STF tasks
        let (accumulate_root, _, _, _) = try_join!(acc_jh, auth_pool_jh, safrole_jh, stats_jh)?;

        // BlockHistory STF (the first half only)
        let manager = self.state_manager.clone();
        spawn_timed("history_jh", async move {
            transition_block_history_parent_root(manager.clone(), parent_state_root).await
        })
        .await??;

        // Collect header markers
        let manager = self.state_manager.clone();
        let safrole_markers = mark_safrole_header_markers(manager, epoch_progressed).await?;
        let offenders_marker = disputes_xt.collect_offender_keys();

        Ok(BlockExecutionOutput {
            offenders_marker,
            safrole_markers,
            accumulate_root,
            reported_packages,
        })
    }

    /// The second EpochEntropy STF
    pub async fn accumulate_entropy(&self, vrf_sig: &VrfSig) -> Result<(), BlockExecutionError> {
        transition_epoch_entropy_per_block(self.state_manager.clone(), vrf_sig.output_hash())
            .await?;
        Ok(())
    }

    /// The second BlockHistory STF
    pub async fn append_block_history(
        &self,
        header_hash: Hash32,
        accumulate_root: Hash32,
        reported_packages: Vec<ReportedWorkPackage>,
    ) -> Result<(), BlockExecutionError> {
        transition_block_history_append(
            self.state_manager.clone(),
            header_hash,
            accumulate_root,
            reported_packages,
        )
        .await?;
        Ok(())
    }
}
