//! Statistics state transition integration tests
use async_trait::async_trait;
use fr_asn_types::statistics::*;
use fr_block::{
    header_db::BlockHeaderDB,
    types::{block::BlockHeader, extrinsics::Extrinsics},
};
use fr_integration::{
    generate_typed_tests,
    stf_harness::{run_test_case, StateTransitionTest},
};
use fr_pvm_types::stats::AccumulateStats;
use fr_state::{
    error::StateManagerError,
    manager::StateManager,
    types::{
        ActiveSet, CoreStats, EpochValidatorStats, OnChainStatistics, ServiceStats, Timeslot,
        ValidatorStats,
    },
};
use fr_transition::{error::TransitionError, state::statistics::transition_onchain_statistics};
use std::sync::Arc;

struct StatisticsTest;

#[async_trait]
impl StateTransitionTest for StatisticsTest {
    const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/statistics";

    type Input = Input;
    type JamInput = JamInput;
    type State = State;
    type JamTransitionOutput = ();
    type Output = Output;
    type ErrorCode = ();

    async fn load_pre_state(
        test_pre_state: &Self::State,
        state_manager: Arc<StateManager>,
    ) -> Result<(), StateManagerError> {
        // Convert ASN pre-state into FastRoll types.
        let pre_onchain_stats = OnChainStatistics {
            validator_stats: ValidatorStats {
                curr: EpochValidatorStats::from(test_pre_state.vals_curr_stats.clone()),
                prev: EpochValidatorStats::from(test_pre_state.vals_last_stats.clone()),
            },
            core_stats: CoreStats::default(),
            service_stats: ServiceStats::default(),
        };

        let pre_timeslot = Timeslot::new(test_pre_state.slot);
        let posterior_active_set = ActiveSet(test_pre_state.curr_validators.clone().into());

        // Load pre-state info the state cache.
        state_manager
            .add_onchain_statistics(pre_onchain_stats)
            .await?;
        state_manager.add_timeslot(pre_timeslot).await?;
        state_manager.add_active_set(posterior_active_set).await?;

        Ok(())
    }

    fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
        // Convert ASN Input into FastRoll types.
        Ok(JamInput {
            timeslot: Timeslot::new(test_input.slot),
            author_index: test_input.author_index,
            extrinsics: Extrinsics::from(test_input.extrinsic.clone()),
        })
    }

    async fn run_state_transition(
        state_manager: Arc<StateManager>,
        _header_db: Arc<BlockHeaderDB>,
        _new_header: &mut BlockHeader,
        jam_input: Self::JamInput,
    ) -> Result<Self::JamTransitionOutput, TransitionError> {
        // Run state transitions.
        let pre_timeslot = state_manager.get_timeslot().await?;
        let next_timeslot = jam_input.timeslot;
        let epoch_progressed = pre_timeslot.epoch() < next_timeslot.epoch();

        transition_onchain_statistics(
            state_manager,
            epoch_progressed,
            jam_input.author_index,
            &jam_input.extrinsics,
            &Vec::new(),
            AccumulateStats::default(),
        )
        .await
    }

    fn map_error_code(_e: TransitionError) -> Self::ErrorCode {
        // No custom error code
    }

    fn extract_output(
        _new_header: &BlockHeader,
        _transition_output: Option<&Self::JamTransitionOutput>,
        _error_code: &Option<Self::ErrorCode>,
    ) -> Self::Output {
        Output
    }

    async fn extract_post_state(
        state_manager: Arc<StateManager>,
        _pre_state: &Self::State,
        _error_code: &Option<Self::ErrorCode>,
    ) -> Result<Self::State, StateManagerError> {
        // Get the posterior state from the state cache.
        let curr_onchain_stats = state_manager.get_onchain_statistics().await?;
        let curr_timeslot = state_manager.get_timeslot().await?;
        let posterior_active_set = state_manager.get_active_set().await?;

        // Convert FastRoll types post-state into ASN post-state
        Ok(State {
            vals_curr_stats: curr_onchain_stats.validator_stats.curr.into(),
            vals_last_stats: curr_onchain_stats.validator_stats.prev.into(),
            slot: curr_timeslot.slot(),
            curr_validators: posterior_active_set.0.into(),
        })
    }
}

generate_typed_tests! {
    StatisticsTest,

    // Empty extrinsic with no epoch change.
    // Only author blocks counter is incremented.
    stats_with_empty_extrinsic_1: "stats_with_empty_extrinsic-1.json",

    // Misc extrinsic information with no epoch change.
    stats_with_epoch_change_1: "stats_with_epoch_change-1.json",

    // Misc extrinsic information with no epoch change.
    stats_with_some_extrinsic_1: "stats_with_some_extrinsic-1.json",
}
