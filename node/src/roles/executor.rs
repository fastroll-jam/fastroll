use crate::utils::spawn_timed;
use fr_block::types::{
    block::{Block, BlockHeaderError},
    extrinsics::disputes::OffendersHeaderMarker,
};
use fr_common::{workloads::ReportedWorkPackage, AccumulateRoot, BlockHeaderHash, ServiceId};
use fr_crypto::{error::CryptoError, traits::VrfSignature};
use fr_pvm_invocation::accumulate::utils::collect_accumulatable_reports;
use fr_state::{
    error::StateManagerError,
    types::{SafroleHeaderMarkers, Timeslot},
};
use fr_storage::node_storage::NodeStorage;
use fr_transition::{
    error::TransitionError,
    state::{
        accumulate::{transition_accumulate_history, transition_accumulate_queue},
        authorizer::transition_auth_pool,
        disputes::transition_disputes,
        entropy::{transition_epoch_entropy_on_epoch_change, transition_epoch_entropy_per_block},
        history::{
            transition_block_history_append, transition_block_history_beefy_belt,
            transition_block_history_parent_root, transition_last_accumulate_outputs,
        },
        reports::{
            transition_reports_clear_availables, transition_reports_eliminate_invalid,
            transition_reports_update_entries,
        },
        safrole::{mark_safrole_header_markers, transition_safrole},
        services::{
            transition_on_accumulate, transition_services_integrate_preimages,
            transition_services_last_accumulate_at, AccountStateChanges,
        },
        statistics::transition_onchain_statistics,
        timeslot::transition_timeslot,
        validators::{transition_active_set, transition_past_set},
    },
};
use thiserror::Error;
use tokio::try_join;
use tracing::{debug_span, instrument};

#[derive(Debug, Error)]
pub enum BlockExecutionError {
    #[error("BlockHeaderError: {0}")]
    BlockHeaderError(#[from] BlockHeaderError),
    #[error("CryptoError: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("StateManagerError: {0}")]
    StateManagerError(#[from] StateManagerError),
    #[error("TransitionError: {0}")]
    TransitionError(#[from] TransitionError),
    #[error("Tokio join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct BlockExecutionOutput {
    pub accumulate_root: AccumulateRoot,
    pub reported_packages: Vec<ReportedWorkPackage>,
    /// A utility field to keep track of changeset of state keys after state transitions (for fuzzing).
    pub account_state_changes: AccountStateChanges,
}

#[derive(Clone, Default)]
pub struct BlockExecutionHeaderMarkers {
    pub offenders_marker: OffendersHeaderMarker,
    pub safrole_markers: SafroleHeaderMarkers,
}

pub struct BlockExecutor;
impl BlockExecutor {
    /// Runs state transition functions required to commit the block header.
    #[instrument(level = "debug", skip_all, name = "stf_1")]
    pub async fn run_state_transition_pre_header_commitment(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<BlockExecutionHeaderMarkers, BlockExecutionError> {
        let disputes_xt = block.extrinsics.disputes.clone();
        let tickets_xt = block.extrinsics.tickets.clone();
        let prev_timeslot = storage.state_manager().get_timeslot().await?;
        let header_timeslot = Timeslot::new(block.header.timeslot_index());
        let parent_state_root = block.header.data.prior_state_root.clone();

        // Timeslot STF
        let manager = storage.state_manager();
        spawn_timed("timeslot_stf", async move {
            transition_timeslot(manager, &header_timeslot).await
        })
        .await??;

        // Epoch progress check
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

        // Finalize `RingCache` after nullifying validator keys in the offenders set
        // of the current Disputes Xt.
        let offenders = disputes_xt.collect_offender_keys();
        let state_manager = storage.state_manager();
        state_manager.nullify_offenders_from_staging_ring_cache(offenders.as_ref())?;

        // Rotate `RingCache` if this block is the first block of a new epoch
        if epoch_progressed {
            state_manager.commit_and_rotate_ring_cache();
        }

        // --- Spawn STF tasks

        // Disputes STF
        let manager = storage.state_manager();
        let disputes_xt_cloned = disputes_xt.clone();
        let disputes_jh = spawn_timed("disputes_stf", async move {
            transition_disputes(manager, &disputes_xt_cloned, offenders.items, prev_timeslot).await
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
        let history_jh = spawn_timed("history_stf", async move {
            transition_block_history_parent_root(manager, parent_state_root).await
        });

        // --- Join: Disputes, Entropy, PastSet, ActiveSet STFs (dependencies for Safrole STF) + History
        let (disputes_res, entropy_res, past_set_res, active_set_res, history_res) = try_join!(
            disputes_jh,
            entropy_jh,
            past_set_jh,
            active_set_jh,
            history_jh
        )?;
        disputes_res?;
        entropy_res?;
        past_set_res?;
        active_set_res?;
        history_res?;

        {
            let span = debug_span!("safrole_stf");
            let _e = span.enter();
            // Safrole STF
            let manager = storage.state_manager();
            spawn_timed("safrole_stf", async move {
                transition_safrole(
                    manager,
                    &prev_timeslot,
                    &curr_timeslot,
                    epoch_progressed,
                    &tickets_xt,
                )
                .await
            })
            .await??;
        }

        // Collect header markers
        let safrole_markers =
            mark_safrole_header_markers(storage.state_manager(), epoch_progressed).await?;
        let offenders_marker = disputes_xt.collect_offender_keys();

        Ok(BlockExecutionHeaderMarkers {
            offenders_marker,
            safrole_markers,
        })
    }

    #[instrument(level = "debug", skip_all, name = "stf_2")]
    pub async fn run_state_transition_post_header_commitment(
        storage: &NodeStorage,
        block: &Block,
        with_ancestors: bool,
    ) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let xt_cloned = block.extrinsics.clone();
        let disputes_xt = block.extrinsics.disputes.clone();
        let assurances_xt = block.extrinsics.assurances.clone();
        let guarantees_xt = block.extrinsics.guarantees.clone();
        let preimages_xt = block.extrinsics.preimages.clone();
        let prev_timeslot = storage.state_manager().get_timeslot_clean().await?;
        let curr_timeslot = storage.state_manager().get_timeslot().await?;
        let parent_hash = block.header.data.parent_hash.clone();
        let author_index = block.header.data.author_index;

        let epoch_progressed = prev_timeslot.epoch() < curr_timeslot.epoch();

        // Reports STF
        let manager = storage.state_manager();
        let header_db = storage.header_db();
        let guarantees_xt_cloned = guarantees_xt.clone();
        let reports_jh = spawn_timed("reports_stf", async move {
            transition_reports_eliminate_invalid(manager.clone(), &disputes_xt, prev_timeslot)
                .await?;
            let available_reports =
                transition_reports_clear_availables(manager.clone(), &assurances_xt, parent_hash)
                    .await?;
            let (reported, reporter_keys) = transition_reports_update_entries(
                manager,
                header_db,
                &guarantees_xt_cloned,
                curr_timeslot,
                with_ancestors,
            )
            .await?;
            Ok::<_, TransitionError>((available_reports, reported, reporter_keys))
        });

        // Second EpochEntropy STF (per-block accumulation)
        // Note: this is a prerequisite for Accumulate STF (η0′ required)
        transition_epoch_entropy_per_block(
            storage.state_manager(),
            block.header.vrf_signature().output_hash()?,
        )
        .await?;

        // Accumulation STFs
        let (available_reports, reported_packages, all_reporter_keys) = reports_jh.await??;
        let acc_queue = storage.state_manager().get_accumulate_queue().await?;
        let acc_history = storage.state_manager().get_accumulate_history().await?;
        let (accumulatable_reports, queued_reports) = collect_accumulatable_reports(
            available_reports.clone(),
            &acc_queue,
            &acc_history,
            curr_timeslot,
        );
        let manager = storage.state_manager();
        let acc_jh = spawn_timed("acc_stf", async move {
            let acc_summary =
                transition_on_accumulate(manager.clone(), &accumulatable_reports).await?;
            transition_accumulate_history(
                manager.clone(),
                &accumulatable_reports,
                acc_summary.accumulated_reports_count,
            )
            .await?;
            transition_accumulate_queue(manager, &queued_reports, prev_timeslot, curr_timeslot)
                .await?;
            Ok::<_, TransitionError>((
                acc_summary.accumulate_stats,
                acc_summary.output_pairs,
                acc_summary.account_state_changes,
            ))
        });
        let (acc_stats, acc_output_pairs, account_state_changes) = acc_jh.await??;

        // LastAccumulateOutputs STF
        let manager = storage.state_manager();
        let last_acc_output_jh = spawn_timed("last_acc_output_stf", async move {
            transition_last_accumulate_outputs(manager, acc_output_pairs).await
        });
        let accumulate_root = last_acc_output_jh.await??;

        // AuthPool STF (post-accumulation)
        let manager = storage.state_manager();
        let guarantees_xt_cloned = guarantees_xt.clone();
        let auth_pool_jh = spawn_timed("auth_pool_stf", async move {
            transition_auth_pool(manager, &guarantees_xt_cloned, curr_timeslot.slot()).await
        });

        // Services last_accumulate_at STF
        let accumulated_services: Vec<ServiceId> = acc_stats.keys().cloned().collect();
        let manager = storage.state_manager();
        let last_acc_at_jh = spawn_timed("last_acc_at_stf", async move {
            transition_services_last_accumulate_at(manager, &accumulated_services).await
        });

        // OnChainStatistics STF
        let manager = storage.state_manager();
        let stats_jh = spawn_timed("stats_stf", async move {
            transition_onchain_statistics(
                manager,
                epoch_progressed,
                author_index,
                &xt_cloned,
                &available_reports,
                &all_reporter_keys,
                acc_stats,
            )
            .await
        });
        // Preimage integration STF
        let manager = storage.state_manager();
        let preimage_jh = spawn_timed("preimage_stf", async move {
            transition_services_integrate_preimages(manager, &preimages_xt).await
        });

        // --- Join: AuthPool, Services(last_accumulate_at), OnChainStatistics, Preimage integration STFs
        let (auth_pool_res, last_acc_at_res, stats_res, preimage_res) =
            try_join!(auth_pool_jh, last_acc_at_jh, stats_jh, preimage_jh)?;
        auth_pool_res?;
        last_acc_at_res?;
        stats_res?;
        preimage_res?;

        Ok(BlockExecutionOutput {
            accumulate_root,
            reported_packages,
            account_state_changes,
        })
    }

    // FIXME: Genesis: WIP
    pub async fn run_genesis_state_transition(
        storage: &NodeStorage,
        block: &Block,
    ) -> Result<BlockExecutionOutput, BlockExecutionError> {
        let guarantees_xt = block.extrinsics.guarantees.clone();
        let tickets_xt = block.extrinsics.tickets.clone();
        let prev_timeslot = storage.state_manager().get_timeslot().await?;
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
        let header_timeslot_index = block.header.timeslot_index();
        let auth_pool_jh = spawn_timed("auth_pool_stf", async move {
            transition_auth_pool(manager, &guarantees_xt, header_timeslot_index).await
        });

        // --- Join: Disputes, Entropy, PastSet, ActiveSet STFs (dependencies for Safrole STF)
        let (entropy_res, past_set_res, active_set_res) =
            try_join!(entropy_jh, past_set_jh, active_set_jh)?;
        entropy_res?;
        past_set_res?;
        active_set_res?;

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
        let (auth_pool_res, safrole_res) = try_join!(auth_pool_jh, safrole_jh)?;
        auth_pool_res?;
        safrole_res?;

        // BlockHistory STF (the first half only)
        let manager = storage.state_manager();
        spawn_timed("history_stf", async move {
            transition_block_history_parent_root(manager.clone(), parent_state_root).await
        })
        .await??;

        // Collect header markers
        let manager = storage.state_manager();
        let _safrole_markers = mark_safrole_header_markers(manager, epoch_progressed).await?;

        Ok(BlockExecutionOutput {
            accumulate_root: AccumulateRoot::default(),
            reported_packages: Vec::new(),
            account_state_changes: AccountStateChanges::default(), // TODO: Check this value for genesis block
        })
    }

    /// The remaining BlockHistory STFs
    #[instrument(level = "debug", skip_all, name = "stf_3")]
    pub async fn append_beefy_belt_and_block_history(
        storage: &NodeStorage,
        accumulate_root: AccumulateRoot,
        header_hash: BlockHeaderHash,
        reported_packages: Vec<ReportedWorkPackage>,
    ) -> Result<(), BlockExecutionError> {
        transition_block_history_beefy_belt(storage.state_manager(), accumulate_root).await?;
        transition_block_history_append(storage.state_manager(), header_hash, reported_packages)
            .await?;
        Ok(())
    }
}
