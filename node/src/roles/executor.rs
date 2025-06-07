use crate::utils::spawn_timed;
use fr_block::types::{
    block::{Block, BlockHeaderError, VrfSig},
    extrinsics::disputes::OffendersHeaderMarker,
};
use fr_common::{workloads::ReportedWorkPackage, Hash32};
use fr_crypto::traits::VrfSignature;
use fr_pvm_invocation::pipeline::{
    accumulate_result_commitment, utils::collect_accumulatable_reports,
};
use fr_state::{
    error::StateManagerError,
    types::{SafroleHeaderMarkers, Timeslot},
};
use fr_storage::node_storage::NodeStorage;
use fr_transition::{
    error::TransitionError,
    procedures::chain_extension::mark_safrole_header_markers,
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
        services::{transition_on_accumulate, transition_services_integrate_preimages},
        statistics::transition_onchain_statistics,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
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

pub struct BlockExecutor;
impl BlockExecutor {
    // TODO: Split this more so that header could be finalized earlier with necessary STFs run first.
    pub async fn run_state_transition(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let xt_cloned = block.extrinsics.clone();
        let disputes_xt = block.extrinsics.disputes.clone();
        let assurances_xt = block.extrinsics.assurances.clone();
        let guarantees_xt = block.extrinsics.guarantees.clone();
        let tickets_xt = block.extrinsics.tickets.clone();
        let preimages_xt = block.extrinsics.preimages.clone();
        let prev_timeslot = storage.state_manager().get_timeslot().await?;
        let header_timeslot = Timeslot::new(block.header.timeslot_index());
        let parent_hash = block.header.data.parent_hash.clone();
        let parent_state_root = block.header.data.prior_state_root.clone();
        let author_index = block.header.data.author_index;

        // Timeslot STF
        let manager = storage.state_manager();
        spawn_timed("timeslot_stf", async move {
            transition_timeslot(manager, &header_timeslot).await
        })
        .await??;

        // Epoch progress check
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

        // --- Spawn STF tasks

        // Disputes STF
        let manager = storage.state_manager();
        let disputes_xt_cloned = disputes_xt.clone();
        let disputes_jh = spawn_timed("disputes_stf", async move {
            transition_disputes(manager, &disputes_xt_cloned, prev_timeslot).await
        });

        // Entropy STF (on-epoch-change transition only)
        let manager = storage.state_manager();
        let entropy_jh = spawn_timed("entropy_stf", async move {
            transition_epoch_entropy_on_epoch_change(manager, epoch_progressed).await
        });

        // PastSet STF
        let manager = storage.state_manager();
        let past_set_jh = spawn_timed("pastset_stf", async move {
            transition_past_set(manager, epoch_progressed).await
        });

        // ActiveSet STF
        let manager = storage.state_manager();
        let active_set_jh = spawn_timed("active_set_stf", async move {
            transition_active_set(manager, epoch_progressed).await
        });

        // BlockHistory STF (the first half only)
        let manager = storage.state_manager();
        spawn_timed("history_stf", async move {
            transition_block_history_parent_root(manager.clone(), parent_state_root).await
        })
        .await??;

        // Reports STF
        // TODO: remove `unwrap`s
        let manager = storage.state_manager();
        let disputes_xt_cloned = disputes_xt.clone();
        let guarantees_xt_cloned = guarantees_xt.clone();
        let reports_jh = spawn_timed("reports_stf", async move {
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
        let manager = storage.state_manager();
        let auth_pool_jh = spawn_timed("auth_pool_stf", async move {
            transition_auth_pool(manager, &guarantees_xt, header_timeslot).await
        });

        // --- Join: Disputes, Entropy, PastSet, ActiveSet STFs (dependencies for Safrole STF)
        #[allow(unused_must_use)]
        try_join!(disputes_jh, entropy_jh, past_set_jh, active_set_jh)?;

        // Safrole STF
        let manager = storage.state_manager();
        let safrole_jh = spawn_timed("safrole_stf", async move {
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
        let manager = storage.state_manager();
        let stats_jh = spawn_timed("stats_stf", async move {
            transition_onchain_statistics(manager, epoch_progressed, author_index, &xt_cloned).await
        });

        // Accumulate STF
        let (available_reports, reported_packages) = reports_jh.await?;
        let acc_queue = storage.state_manager().get_accumulate_queue().await?;
        let acc_history = storage.state_manager().get_accumulate_history().await?;
        let (accumulatable_reports, queued_reports) = collect_accumulatable_reports(
            available_reports,
            &acc_queue,
            &acc_history,
            prev_timeslot.slot(),
        );
        let manager = storage.state_manager();
        let acc_jh = spawn_timed("acc_stf", async move {
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

        // Preimage integration STF
        let manager = storage.state_manager();
        spawn_timed("preimage_stf", async move {
            transition_services_integrate_preimages(manager.clone(), &preimages_xt).await
        })
        .await??;

        // Collect header markers
        let manager = storage.state_manager();
        let safrole_markers = mark_safrole_header_markers(manager, epoch_progressed).await?;
        let offenders_marker = disputes_xt.collect_offender_keys();

        Ok(BlockExecutionOutput {
            offenders_marker,
            safrole_markers,
            accumulate_root,
            reported_packages,
        })
    }

    // FIXME: WIP
    pub async fn run_genesis_state_transition(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let guarantees_xt = block.extrinsics.guarantees.clone();
        let tickets_xt = block.extrinsics.tickets.clone();
        let prev_timeslot = storage.state_manager().get_timeslot().await?;
        let header_timeslot = Timeslot::new(block.header.timeslot_index());
        let parent_state_root = block.header.data.prior_state_root.clone();

        // Epoch progress check
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

        // --- Spawn STF tasks

        // Entropy STF (on-epoch-change transition only)
        let manager = storage.state_manager();
        let entropy_jh = spawn_timed("entropy_stf", async move {
            transition_epoch_entropy_on_epoch_change(manager, epoch_progressed).await
        });

        // PastSet STF
        let manager = storage.state_manager();
        let past_set_jh = spawn_timed("pastset_stf", async move {
            transition_past_set(manager, epoch_progressed).await
        });

        // ActiveSet STF
        let manager = storage.state_manager();
        let active_set_jh = spawn_timed("active_set_stf", async move {
            transition_active_set(manager, epoch_progressed).await
        });

        // Authorizer STF
        let manager = storage.state_manager();
        let auth_pool_jh = spawn_timed("auth_pool_stf", async move {
            transition_auth_pool(manager, &guarantees_xt, header_timeslot).await
        });

        // --- Join: Disputes, Entropy, PastSet, ActiveSet STFs (dependencies for Safrole STF)
        #[allow(unused_must_use)]
        try_join!(entropy_jh, past_set_jh, active_set_jh)?;

        // Safrole STF
        let manager = storage.state_manager();
        let safrole_jh = spawn_timed("safrole_stf", async move {
            transition_safrole(
                manager,
                &prev_timeslot,
                &curr_timeslot,
                epoch_progressed,
                &tickets_xt,
            )
            .await
        });
        // Join remaining STF tasks
        let (_, _) = try_join!(auth_pool_jh, safrole_jh)?;

        // BlockHistory STF (the first half only)
        let manager = storage.state_manager();
        spawn_timed("history_stf", async move {
            transition_block_history_parent_root(manager.clone(), parent_state_root).await
        })
        .await??;

        // Collect header markers
        let manager = storage.state_manager();
        let safrole_markers = mark_safrole_header_markers(manager, epoch_progressed).await?;

        Ok(BlockExecutionOutput {
            offenders_marker: OffendersHeaderMarker::default(),
            safrole_markers,
            accumulate_root: Hash32::default(),
            reported_packages: Vec::new(),
        })
    }

    /// The second EpochEntropy STF
    pub async fn accumulate_entropy(
        storage: &NodeStorage,
        vrf_sig: &VrfSig,
    ) -> Result<(), BlockExecutionError> {
        transition_epoch_entropy_per_block(storage.state_manager(), vrf_sig.output_hash()).await?;
        Ok(())
    }

    /// The second BlockHistory STF
    pub async fn append_block_history(
        storage: &NodeStorage,
        header_hash: Hash32,
        accumulate_root: Hash32,
        reported_packages: Vec<ReportedWorkPackage>,
    ) -> Result<(), BlockExecutionError> {
        transition_block_history_append(
            storage.state_manager(),
            header_hash,
            accumulate_root,
            reported_packages,
        )
        .await?;
        Ok(())
    }
}
