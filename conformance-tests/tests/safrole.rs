//! Safrole state transition conformance tests
mod safrole {
    use async_trait::async_trait;
    use fr_asn_types::types::{common::*, safrole::*};
    use fr_block::types::{
        block::BlockHeader,
        extrinsics::tickets::{TicketsXt, TicketsXtEntry},
    };
    use fr_common::Hash32;
    use fr_conformance_tests::{
        err_map::safrole::map_error_to_custom_code,
        generate_typed_tests,
        harness::{run_test_case, StateTransitionTest},
    };
    use fr_crypto::types::Ed25519PubKey;
    use fr_state::{
        cache::StateMut,
        error::StateManagerError,
        manager::StateManager,
        types::{
            ActiveSet, DisputesState, EpochEntropy, PastSet, SafroleHeaderMarkers, SafroleState,
            StagingSet, Timeslot,
        },
    };
    use fr_transition::{
        error::TransitionError,
        procedures::chain_extension::mark_safrole_header_markers,
        state::{
            entropy::{
                transition_epoch_entropy_on_epoch_change, transition_epoch_entropy_per_block,
            },
            safrole::transition_safrole,
            timeslot::transition_timeslot,
            validators::{transition_active_set, transition_past_set},
        },
    };
    use std::sync::Arc;

    struct SafroleTest;

    #[async_trait]
    impl StateTransitionTest for SafroleTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/stf/safrole/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type JamTransitionOutput = ();
        type Output = Output;
        type ErrorCode = SafroleErrorCode;

        async fn load_pre_state(
            test_pre_state: &Self::State,
            state_manager: Arc<StateManager>,
        ) -> Result<(), StateManagerError> {
            // Convert ASN pre-state into FastRoll types.
            let pre_safrole = SafroleState::from(test_pre_state);
            let pre_entropy = EpochEntropy::from(test_pre_state.eta.clone());
            let pre_staging_set =
                StagingSet(validators_data_to_validator_set(&test_pre_state.iota));
            let pre_active_set = ActiveSet(validators_data_to_validator_set(&test_pre_state.kappa));
            let pre_past_set = PastSet(validators_data_to_validator_set(&test_pre_state.lambda));
            let pre_timeslot = Timeslot::new(test_pre_state.tau);
            let pre_post_offenders = test_pre_state
                .post_offenders
                .iter()
                .map(|k| Ed25519PubKey::from(*k))
                .collect();

            // Load pre-state into the state cache.
            state_manager.add_safrole(pre_safrole).await?;
            state_manager.add_staging_set(pre_staging_set).await?;
            state_manager.add_active_set(pre_active_set).await?;
            state_manager.add_past_set(pre_past_set).await?;
            state_manager.add_epoch_entropy(pre_entropy).await?;
            state_manager.add_timeslot(pre_timeslot).await?;
            state_manager.add_disputes(DisputesState::default()).await?;
            state_manager
                .with_mut_disputes(StateMut::Update, |disputes| {
                    disputes.punish_set = pre_post_offenders;
                })
                .await?;

            Ok(())
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into FastRoll types.
            let input_timeslot = Timeslot::new(test_input.slot);
            let input_header_entropy_hash = test_input.entropy;
            let input_ticket_entries: Vec<TicketsXtEntry> = test_input
                .extrinsic
                .clone()
                .into_iter()
                .map(AsnTicketEnvelope::into)
                .collect();

            Ok(JamInput {
                slot: input_timeslot,
                entropy: Hash32::from(input_header_entropy_hash),
                extrinsic: TicketsXt {
                    items: input_ticket_entries,
                },
            })
        }

        async fn run_state_transition(
            state_manager: Arc<StateManager>,
            new_header: &mut BlockHeader,
            jam_input: Self::JamInput,
        ) -> Result<Self::JamTransitionOutput, TransitionError> {
            // let (input_timeslot, input_header_entropy_hash, input_extrinsic) = jam_input;

            // Run the chain extension procedure.
            let pre_timeslot = state_manager.get_timeslot().await?;
            transition_timeslot(state_manager.clone(), &jam_input.slot).await?;
            let curr_timeslot = state_manager.get_timeslot().await?;
            let epoch_progressed = pre_timeslot.epoch() < curr_timeslot.epoch();
            transition_epoch_entropy_on_epoch_change(state_manager.clone(), epoch_progressed)
                .await?;
            transition_epoch_entropy_per_block(state_manager.clone(), jam_input.entropy).await?;
            transition_past_set(state_manager.clone(), epoch_progressed).await?;
            transition_active_set(state_manager.clone(), epoch_progressed).await?;
            transition_safrole(
                state_manager.clone(),
                &pre_timeslot,
                &curr_timeslot,
                epoch_progressed,
                &jam_input.extrinsic,
            )
            .await?;

            let markers = mark_safrole_header_markers(state_manager, epoch_progressed).await?;
            if let Some(epoch_marker) = markers.epoch_marker {
                new_header.set_epoch_marker(epoch_marker);
            }
            if let Some(winning_tickets_marker) = markers.winning_tickets_marker {
                new_header.set_winning_tickets_marker(winning_tickets_marker);
            }

            Ok(())
        }

        fn map_error_code(e: TransitionError) -> Self::ErrorCode {
            map_error_to_custom_code(e)
        }

        fn extract_output(
            new_header: &BlockHeader,
            _transition_output: Option<&Self::JamTransitionOutput>,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            if let Some(error_code) = error_code {
                return Output::err(error_code.clone());
            }

            // Convert FastRoll output into ASN Output.
            let curr_header_epoch_marker = new_header.epoch_marker().cloned();
            let curr_header_winning_tickets_marker = new_header.winning_tickets_marker().cloned();

            let output_marks = SafroleHeaderMarkers {
                epoch_marker: curr_header_epoch_marker,
                winning_tickets_marker: curr_header_winning_tickets_marker,
            };

            Output::ok(output_marks.into())
        }

        async fn extract_post_state(
            state_manager: Arc<StateManager>,
            pre_state: &Self::State,
            error_code: &Option<Self::ErrorCode>,
        ) -> Result<Self::State, StateManagerError> {
            if error_code.is_some() {
                // Rollback state transition
                return Ok(pre_state.clone());
            }

            // Get the posterior state from the state cache.
            let curr_safrole = state_manager.get_safrole().await?;
            let curr_staging_set = state_manager.get_staging_set().await?;
            let curr_active_set = state_manager.get_active_set().await?;
            let curr_past_set = state_manager.get_past_set().await?;
            let curr_entropy = state_manager.get_epoch_entropy().await?;
            let curr_timeslot = state_manager.get_timeslot().await?;
            let curr_post_offenders = state_manager.get_disputes().await?.punish_set;

            // Convert FastRoll types post-state into ASN post-state
            let (gamma_k, gamma_a, gamma_s, gamma_z) = safrole_state_to_gammas(curr_safrole);

            Ok(State {
                tau: curr_timeslot.slot(),
                eta: curr_entropy.into(),
                lambda: validator_set_to_validators_data(&curr_past_set),
                kappa: validator_set_to_validators_data(&curr_active_set),
                gamma_k,
                iota: validator_set_to_validators_data(&curr_staging_set),
                gamma_a,
                gamma_s,
                gamma_z,
                post_offenders: curr_post_offenders
                    .into_iter()
                    .map(AsnEd25519Key::from)
                    .collect(),
            })
        }
    }

    generate_typed_tests! {
        SafroleTest,

        // Success
        // Progress by one slot.
        // Randomness accumulator is updated.
        enact_epoch_change_with_no_tickets_1: "enact-epoch-change-with-no-tickets-1.json",

        // Fail
        // Progress from slot X to slot X.
        // Timeslot must be strictly monotonic.
        enact_epoch_change_with_no_tickets_2: "enact-epoch-change-with-no-tickets-2.json",

        // Success
        // Progress from a slot at the begin of the epoch to a slot in the epoch's tail.
        // Tickets mark is not generated (no enough tickets).
        enact_epoch_change_with_no_tickets_3: "enact-epoch-change-with-no-tickets-3.json",

        // Success
        // Progress from epoch's tail to next epoch.
        // Authorities and entropies are rotated. Epoch mark is generated.
        enact_epoch_change_with_no_tickets_4: "enact-epoch-change-with-no-tickets-4.json",

        // Success
        // Progress skipping epochs with a full tickets accumulator.
        // Tickets mark is not generated. Accumulated tickets discarded. Fallback method enacted.
        skip_epochs_1: "skip-epochs-1.json",

        // Success
        // Progress to next epoch by skipping epochs tail with a full tickets accumulator.
        // Tickets mark has no chance to be generated. Accumulated tickets discarded. Fallback method enacted.
        skip_epoch_tail_1: "skip-epoch-tail-1.json",

        // Fail
        // Submit an extrinsic with a bad ticket attempt number.
        publish_tickets_no_mark_1: "publish-tickets-no-mark-1.json",

        // Success
        // Submit good tickets extrinsics from some authorities.
        publish_tickets_no_mark_2: "publish-tickets-no-mark-2.json",

        // Fail
        // Submit one ticket already recorded in the state.
        publish_tickets_no_mark_3: "publish-tickets-no-mark-3.json",

        // Fail
        // Submit tickets in bad order.
        publish_tickets_no_mark_4: "publish-tickets-no-mark-4.json",

        // Fail
        // Submit tickets with bad ring proof.
        publish_tickets_no_mark_5: "publish-tickets-no-mark-5.json",

        // Success
        // Submit some tickets.
        publish_tickets_no_mark_6: "publish-tickets-no-mark-6.json",

        // Fail
        // Submit tickets when epoch's lottery is over.
        publish_tickets_no_mark_7: "publish-tickets-no-mark-7.json",

        // Success
        // Progress into epoch tail, closing the epoch's lottery.
        // No enough tickets, thus no tickets mark is generated.
        publish_tickets_no_mark_8: "publish-tickets-no-mark-8.json",

        // Success
        // Progress into next epoch with no enough tickets.
        // Accumulated tickets are discarded. Epoch mark generated. Fallback method enacted.
        publish_tickets_no_mark_9: "publish-tickets-no-mark-9.json",

        // Success
        // Publish some tickets with an almost full tickets accumulator.
        // Tickets accumulator is not full yet. No ticket is dropped from accumulator.
        publish_tickets_with_mark_1: "publish-tickets-with-mark-1.json",

        // Success
        // Publish some tickets filling the accumulator.
        // Two old tickets are removed from the accumulator.
        publish_tickets_with_mark_2: "publish-tickets-with-mark-2.json",

        // Success
        // Publish some tickets with a full accumulator.
        // Some old ticket are removed to make space for new ones.
        publish_tickets_with_mark_3: "publish-tickets-with-mark-3.json",

        // Success
        // With a full accumulator, conclude the lottery.
        // Tickets mark is generated.
        publish_tickets_with_mark_4: "publish-tickets-with-mark-4.json",

        // Success
        // With a published tickets mark, progress into next epoch.
        // Epoch mark is generated. Tickets are enacted.
        publish_tickets_with_mark_5: "publish-tickets-with-mark-5.json",

        // Success
        // On epoch change we recompute the ring commitment.
        // One of the keys to be used is invalidated (zeroed out) because it belongs to the (posterior) offenders list.
        // One of the keys is just invalid (i.e. it can't be decoded into a valid Bandersnatch point).
        // Both the invalid keys are replaced with the padding point during ring commitment computation.
        enact_epoch_change_with_padding_1: "enact-epoch-change-with-padding-1.json",
    }
}
