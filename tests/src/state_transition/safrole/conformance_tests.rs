//! Safrole state transition conformance tests
#[cfg(test)]
mod tests {
    use crate::{
        asn_types::{
            validator_set_to_validators_data, validators_data_to_validator_set, ByteArray32,
            TicketEnvelope,
        },
        generate_typed_tests,
        safrole::{
            asn_types::{Input, JamInput, Output, SafroleErrorCode, State},
            utils::{
                entropy_accumulator_to_eta, map_error_to_custom_code, safrole_state_to_gammas,
            },
        },
        state_transition::state_transition_test::{run_test_case, StateTransitionTest},
    };
    use rjam_common::ByteArray;
    use rjam_db::BlockHeaderDB;
    use rjam_state::{StateManager, StateWriteOp};
    use rjam_transition::{
        error::TransitionError,
        header::{set_header_epoch_marker, set_header_winning_tickets_marker},
        procedures::chain_extension::{mark_safrole_header_markers, SafroleHeaderMarkers},
        state::{
            entropy::transition_entropy_accumulator,
            safrole::transition_safrole,
            timeslot::transition_timeslot,
            validators::{transition_active_set, transition_past_set},
        },
    };
    use rjam_types::{
        extrinsics::tickets::{TicketsExtrinsic, TicketsExtrinsicEntry},
        state::*,
        state_utils::{StateEntryType, StateKeyConstant},
    };

    struct SafroleTest;

    impl StateTransitionTest for SafroleTest {
        const PATH_PREFIX: &'static str = "jamtestvectors-polkajam/safrole/tiny";

        type Input = Input;
        type JamInput = JamInput;
        type State = State;
        type Output = Output;
        type ErrorCode = SafroleErrorCode;

        fn setup_state_manager(
            test_pre_state: &Self::State,
        ) -> Result<StateManager, TransitionError> {
            // Convert ASN pre-state into RJAM types.
            let prior_safrole = SafroleState::from(test_pre_state);
            let prior_entropy = EntropyAccumulator::from(test_pre_state);
            let prior_staging_set =
                StagingSet(validators_data_to_validator_set(&test_pre_state.iota));
            let prior_active_set =
                ActiveSet(validators_data_to_validator_set(&test_pre_state.kappa));
            let prior_past_set = PastSet(validators_data_to_validator_set(&test_pre_state.lambda));
            let prior_timeslot = Timeslot::new(test_pre_state.tau);
            let prior_post_offenders = test_pre_state
                .post_offenders
                .iter()
                .map(|key| ByteArray::new(key.0))
                .collect();

            // Initialize StateManager.
            let mut state_manager = StateManager::new_for_test();

            // Load pre-state into the state cache.
            state_manager.load_state_for_test(
                StateKeyConstant::SafroleState,
                StateEntryType::SafroleState(prior_safrole),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::StagingSet,
                StateEntryType::StagingSet(prior_staging_set),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::ActiveSet,
                StateEntryType::ActiveSet(prior_active_set),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::PastSet,
                StateEntryType::PastSet(prior_past_set),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::EntropyAccumulator,
                StateEntryType::EntropyAccumulator(prior_entropy),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::Timeslot,
                StateEntryType::Timeslot(prior_timeslot),
            );
            state_manager.load_state_for_test(
                StateKeyConstant::DisputesState,
                StateEntryType::DisputesState(DisputesState::default()),
            );
            state_manager.with_mut_disputes(StateWriteOp::Update, |disputes| {
                disputes.punish_set = prior_post_offenders;
            })?;

            Ok(state_manager)
        }

        fn convert_input_type(test_input: &Self::Input) -> Result<Self::JamInput, TransitionError> {
            // Convert ASN Input into RJAM types.
            let input_timeslot = Timeslot::new(test_input.slot);
            let input_header_entropy_hash = test_input.entropy.0;
            let input_ticket_entries: Vec<TicketsExtrinsicEntry> = test_input
                .extrinsic
                .clone()
                .into_iter()
                .map(TicketEnvelope::into)
                .collect();

            Ok(JamInput {
                slot: input_timeslot,
                entropy: ByteArray::new(input_header_entropy_hash),
                extrinsic: TicketsExtrinsic {
                    items: input_ticket_entries,
                },
            })
        }

        fn run_state_transition(
            state_manager: &StateManager,
            header_db: &mut BlockHeaderDB,
            jam_input: &Self::JamInput,
        ) -> Result<(), TransitionError> {
            // let (input_timeslot, input_header_entropy_hash, input_extrinsic) = jam_input;

            // Run the chain extension procedure.
            let prior_timeslot = state_manager.get_timeslot()?;
            transition_timeslot(&state_manager, &jam_input.slot)?;
            let current_timeslot = state_manager.get_timeslot()?;
            let epoch_progressed = prior_timeslot.epoch() < current_timeslot.epoch();
            transition_entropy_accumulator(
                &state_manager,
                epoch_progressed,
                jam_input.entropy.clone(),
            )?;
            transition_past_set(&state_manager, epoch_progressed)?;
            transition_active_set(&state_manager, epoch_progressed)?;
            transition_safrole(
                &state_manager,
                &prior_timeslot,
                epoch_progressed,
                &jam_input.extrinsic,
            )?;

            let markers = mark_safrole_header_markers(&state_manager, epoch_progressed)?;
            if let Some(epoch_marker) = markers.epoch_marker.as_ref() {
                set_header_epoch_marker(header_db, epoch_marker)?;
            }
            if let Some(winning_tickets_marker) = markers.winning_tickets_marker.as_ref() {
                set_header_winning_tickets_marker(header_db, winning_tickets_marker)?;
            }

            Ok(())
        }

        fn map_error_code(e: TransitionError) -> Self::ErrorCode {
            map_error_to_custom_code(e)
        }

        fn extract_output(
            header_db: &BlockHeaderDB,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::Output {
            if let Some(error_code) = error_code {
                return Output::err(error_code.clone());
            }

            // Convert RJAM output into ASN Output.
            let staging_header = header_db.get_staging_header().cloned().unwrap();
            let current_header_epoch_marker = staging_header.epoch_marker;
            let current_header_winning_tickets_marker = staging_header.winning_tickets_marker;

            let output_marks = SafroleHeaderMarkers {
                epoch_marker: current_header_epoch_marker,
                winning_tickets_marker: current_header_winning_tickets_marker,
            };

            Output::ok(output_marks.into())
        }

        fn extract_post_state(
            state_manager: &StateManager,
            pre_state: &Self::State,
            error_code: &Option<Self::ErrorCode>,
        ) -> Self::State {
            if error_code.is_some() {
                // Rollback state transition
                return pre_state.clone();
            }

            // Get the posterior state from the state cache.
            let current_safrole = state_manager.get_safrole().unwrap();
            let current_staging_set = state_manager.get_staging_set().unwrap();
            let current_active_set = state_manager.get_active_set().unwrap();
            let current_past_set = state_manager.get_past_set().unwrap();
            let current_entropy = state_manager.get_entropy_accumulator().unwrap();
            let current_timeslot = state_manager.get_timeslot().unwrap();
            let current_post_offenders = state_manager.get_disputes().unwrap().punish_set;

            // Convert RJAM types post-state into ASN post-state
            let (gamma_k, gamma_a, gamma_s, gamma_z) = safrole_state_to_gammas(&current_safrole);

            State {
                tau: current_timeslot.slot(),
                eta: entropy_accumulator_to_eta(&current_entropy),
                lambda: validator_set_to_validators_data(&current_past_set),
                kappa: validator_set_to_validators_data(&current_active_set),
                gamma_k,
                iota: validator_set_to_validators_data(&current_staging_set),
                gamma_a,
                gamma_s,
                gamma_z,
                post_offenders: current_post_offenders
                    .into_iter()
                    .map(ByteArray32::from)
                    .collect(),
            }
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
        // TODO - check `TICKET_SUBMISSION_DEADLINE_SLOT` value (it seems this case should not run in fallback mode)
        // skip_epochs_1: "skip-epochs-1.json",

        // Success
        // Progress to next epoch by skipping epochs tail with a full tickets accumulator.
        // Tickets mark has no chance to be generated. Accumulated tickets discarded. Fallback method enacted.
        skip_epoch_tail_1: "skip-epoch-tail-1.json",

        // Fail
        // Submit an extrinsic with a bad ticket attempt number.
        // TODO - check ticket ring proof hashes (bad ticket order error)
        // publish_tickets_no_mark_1: "publish-tickets-no-mark-1.json",

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
