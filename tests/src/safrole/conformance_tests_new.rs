#[cfg(test)]
mod tests {

    //
    // Safrole state transition conformance tests
    //

    use crate::safrole::{
        asn_types::{Input, Output, OutputMarks, State, Testcase, TicketEnvelope},
        utils::{map_error_to_custom_code, StateBuilder},
    };
    use rjam_state::{StateEntryType, StateKeyConstant, StateManager, StateWriteOp};
    use rjam_transition::{
        components::{
            entropy_new::transition_entropy_accumulator,
            safrole_new::transition_safrole,
            timeslot_new::transition_timeslot,
            validators_new::{transition_active_set, transition_past_set},
        },
        procedures::chain_extension::mark_safrole_header_markers,
    };
    use rjam_types::{
        extrinsics::tickets::TicketExtrinsicEntry,
        state::{disputes::DisputesState, timeslot::Timeslot},
    };
    use std::{error::Error, fs};

    // Load a test case from the test vector path
    fn load_test_case(path: &str) -> Result<Testcase, ()> {
        let full_path = format!(
            "{}/jamtestvectors-new-safrole/{}",
            env!("CARGO_MANIFEST_DIR"),
            path
        );
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_case)
    }

    // Returns the actual post state, to be compared with the test post state.
    fn run_state_transition(
        test_input: Input,
        test_pre_state: State,
    ) -> Result<(State, Output), Box<dyn Error>> {
        // Convert ASN pre-state into RJAM types.
        let prior_safrole = test_pre_state.into_safrole_state()?;
        let (prior_staging_set, prior_active_set, prior_past_set) =
            test_pre_state.into_validator_sets()?;
        let prior_entropy = test_pre_state.into_entropy_accumulator()?;
        let prior_timeslot = test_pre_state.into_timeslot()?;

        // Initialize StateManager.
        let mut state_manager = StateManager::new_for_test();

        // Load pre-state into the StateCache.
        // TODO: Update the generic `load_state_for_test` method to be generic.
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

        // Convert ASN Input into RJAM types.
        let input_timeslot = Timeslot::new(test_input.slot);
        let input_header_entropy_hash = test_input.entropy.0;
        let input_punished_set = test_input.post_offenders.iter().map(|key| key.0).collect();
        state_manager.load_state_for_test(
            StateKeyConstant::DisputesState,
            StateEntryType::DisputesState(DisputesState::default()),
        );
        state_manager.with_mut_disputes(StateWriteOp::Update, |disputes| {
            disputes.set_punish_set(input_punished_set);
        })?;
        let input_ticket_extrinsics: Vec<TicketExtrinsicEntry> = test_input
            .extrinsic
            .into_iter()
            .map(TicketEnvelope::into)
            .collect();

        // Run the chain extension procedure.
        transition_timeslot(&state_manager, &input_timeslot)?;
        let current_timeslot = state_manager.get_timeslot()?;
        let epoch_progressed = prior_timeslot.epoch() < current_timeslot.epoch();
        transition_entropy_accumulator(
            &state_manager,
            epoch_progressed,
            input_header_entropy_hash,
        )?;
        transition_past_set(&state_manager, epoch_progressed)?;
        transition_active_set(&state_manager, epoch_progressed)?;
        transition_safrole(
            &state_manager,
            &prior_timeslot,
            epoch_progressed,
            &input_ticket_extrinsics,
        )?;

        // Convert RJAM output into ASN Output.
        let markers = mark_safrole_header_markers(&state_manager, epoch_progressed)?;
        let output_marks = OutputMarks::from(markers);

        // Get the posterior state from the StateCache.
        let current_safrole = state_manager.get_safrole()?;
        let current_staging_set = state_manager.get_staging_set()?;
        let current_active_set = state_manager.get_active_set()?;
        let current_past_set = state_manager.get_past_set()?;
        let current_entropy = state_manager.get_entropy_accumulator()?;
        let current_timeslot = state_manager.get_timeslot()?;

        // Convert RJAM types post-state into ASN post-state
        let builder = StateBuilder::new();
        let post_state = builder
            .from_safrole_state(&current_safrole)?
            .from_validator_sets(&current_staging_set, &current_active_set, &current_past_set)?
            .from_entropy_accumulator(&current_entropy)?
            .from_timeslot(&current_timeslot)?
            .build()?;

        Ok((post_state, Output::ok(output_marks)))
    }

    fn run_state_transition_with_error_mapping(
        test_input: Input,
        test_pre_state: State,
    ) -> Result<(State, Output), Box<dyn Error>> {
        match run_state_transition(test_input, test_pre_state.clone()) {
            Ok(result) => Ok(result),
            Err(e) => Ok((test_pre_state, Output::err(map_error_to_custom_code(e)))), // represents rollback mechanism for state transition failures
        }
    }

    fn run_test_case(path: &str) -> Result<(), Box<dyn Error>> {
        let test_case = load_test_case(path).expect("Failed to load test vector.");
        let expected_post_state = test_case.post_state; // The expected post state.

        let (post_state, output) =
            run_state_transition_with_error_mapping(test_case.input, test_case.pre_state)?;

        // Assertion on the post state
        // assert_eq!(post_state, expected_post_state);
        assert_eq!(post_state.tau, expected_post_state.tau);
        assert_eq!(post_state.eta, expected_post_state.eta);
        assert_eq!(post_state.lambda, expected_post_state.lambda);
        assert_eq!(post_state.kappa, expected_post_state.kappa);
        assert_eq!(post_state.gamma_k, expected_post_state.gamma_k);
        assert_eq!(post_state.iota, expected_post_state.iota);
        assert_eq!(post_state.gamma_a, expected_post_state.gamma_a);
        assert_eq!(post_state.gamma_s, expected_post_state.gamma_s);
        assert_eq!(post_state.gamma_z, expected_post_state.gamma_z);

        // Assertion on the state transition output
        assert_eq!(output, test_case.output);
        Ok(())
    }

    macro_rules! generate_tests {
        ($($name:ident: $path:expr,)*) => {
            $(
                #[test]
                fn $name() -> Result<(), Box<dyn Error>> {
                    run_test_case($path)
                }
            )*
        }
    }

    generate_tests! {
        // Success
        // Progress by one slot.
        // Randomness accumulator is updated.
        test_enact_epoch_change_with_no_tickets_1: "safrole/tiny/enact-epoch-change-with-no-tickets-1.json",

        // Fail
        // Progress from slot X to slot X.
        // Timeslot must be strictly monotonic.
        test_enact_epoch_change_with_no_tickets_2: "safrole/tiny/enact-epoch-change-with-no-tickets-2.json",

        // Success
        // Progress from a slot at the begin of the epoch to a slot in the epoch's tail.
        // Tickets mark is not generated (no enough tickets).
        test_enact_epoch_change_with_no_tickets_3: "safrole/tiny/enact-epoch-change-with-no-tickets-3.json",

        // Success
        // Progress from epoch's tail to next epoch.
        // Authorities and entropies are rotated. Epoch mark is generated.
        test_enact_epoch_change_with_no_tickets_4: "safrole/tiny/enact-epoch-change-with-no-tickets-4.json",

        // Success
        // Progress skipping epochs with a full tickets accumulator.
        // Tickets mark is not generated. Accumulated tickets discarded. Fallback method enacted.
        // TODO - check `TICKET_SUBMISSION_DEADLINE_SLOT` value (it seems this case should not run in fallback mode)
        // skip_epochs_1: "safrole/tiny/skip-epochs-1.json",

        // Success
        // Progress to next epoch by skipping epochs tail with a full tickets accumulator.
        // Tickets mark has no chance to be generated. Accumulated tickets discarded. Fallback method enacted.
        skip_epoch_tail_1: "safrole/tiny/skip-epoch-tail-1.json",

        // Fail
        // Submit an extrinsic with a bad ticket attempt number.
        publish_tickets_no_mark_1: "safrole/tiny/publish-tickets-no-mark-1.json",

        // Success
        // Submit good tickets extrinsics from some authorities.
        publish_tickets_no_mark_2: "safrole/tiny/publish-tickets-no-mark-2.json",

        // Fail
        // Submit one ticket already recorded in the state.
        publish_tickets_no_mark_3: "safrole/tiny/publish-tickets-no-mark-3.json",

        // Fail
        // Submit tickets in bad order.
        publish_tickets_no_mark_4: "safrole/tiny/publish-tickets-no-mark-4.json",

        // Fail
        // Submit tickets with bad ring proof.
        publish_tickets_no_mark_5: "safrole/tiny/publish-tickets-no-mark-5.json",

        // Success
        // Submit some tickets.
        publish_tickets_no_mark_6: "safrole/tiny/publish-tickets-no-mark-6.json",

        // Fail
        // Submit tickets when epoch's lottery is over.
        // publish_tickets_no_mark_7: "safrole/tiny/publish-tickets-no-mark-7.json",

        // Success
        // Progress into epoch tail, closing the epoch's lottery.
        // No enough tickets, thus no tickets mark is generated.
        publish_tickets_no_mark_8: "safrole/tiny/publish-tickets-no-mark-8.json",

        // Success
        // Progress into next epoch with no enough tickets.
        // Accumulated tickets are discarded. Epoch mark generated. Fallback method enacted.
        publish_tickets_no_mark_9: "safrole/tiny/publish-tickets-no-mark-9.json",

        // Success
        // Publish some tickets with an almost full tickets accumulator.
        // Tickets accumulator is not full yet. No ticket is dropped from accumulator.
        publish_tickets_with_mark_1: "safrole/tiny/publish-tickets-with-mark-1.json",

        // Success
        // Publish some tickets filling the accumulator.
        // Two old tickets are removed from the accumulator.
        publish_tickets_with_mark_2: "safrole/tiny/publish-tickets-with-mark-2.json",

        // Success
        // Publish some tickets with a full accumulator.
        // Some old ticket are removed to make space for new ones.
        publish_tickets_with_mark_3: "safrole/tiny/publish-tickets-with-mark-3.json",

        // Success
        // With a full accumulator, conclude the lottery.
        // Tickets mark is generated.
        publish_tickets_with_mark_4: "safrole/tiny/publish-tickets-with-mark-4.json",

        // Success
        // With a published tickets mark, progress into next epoch.
        // Epoch mark is generated. Tickets are enacted.
        publish_tickets_with_mark_5: "safrole/tiny/publish-tickets-with-mark-5.json",

        // Success
        // On epoch change we recompute the ring commitment.
        // One of the keys to be used is invalidated (zeroed out) because it belongs to the (posterior) offenders list.
        // One of the keys is just invalid (i.e. it can't be decoded into a valid Bandersnatch point).
        // Both the invalid keys are replaced with the padding point during ring commitment computation.
        // enact_epoch_change_with_padding_1: "safrole/tiny/enact-epoch-change-with-padding-1.json", // FIXME
    }
}
