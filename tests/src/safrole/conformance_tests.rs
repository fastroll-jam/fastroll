#[cfg(test)]
mod tests {
    use crate::safrole::{
        asn_types::{Input, Output, OutputMarks, State, Testcase, TicketEnvelope, EPOCH_LENGTH},
        utils::{map_error_to_custom_code, StateBuilder},
    };
    use rjam_transition::{
        components::{
            entropy::EntropyAccumulatorContext,
            safrole::SafroleStateContext,
            timeslot::TimeslotContext,
            validators::{
                ActiveValidatorSetContext, PastValidatorSetContext, StagingValidatorSetContext,
            },
        },
        Transition,
    };
    use rjam_types::state::timeslot::Timeslot;
    use std::{error::Error, fs};

    //
    // Safrole state transition conformance tests
    //

    // Load a test case from the test vector path
    fn load_test_case(path: &'static str) -> Result<Testcase, ()> {
        let full_path = format!("{}/jamtestvectors/{}", env!("CARGO_MANIFEST_DIR"), path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_case)
    }

    // Returns the actual post state, to be compared with the test post state.
    fn run_state_transition(
        test_input: Input,
        test_pre_state: State,
    ) -> Result<State, Box<dyn Error>> {
        //
        // Conversion: Test vector pre-state => Jam pre-state
        //

        let mut safrole_state = test_pre_state.into_safrole_state()?;
        let (mut staging_set, mut active_set, mut past_set) =
            test_pre_state.into_validator_sets()?;
        let mut entropy_acc = test_pre_state.into_entropy_accumulator()?;
        let mut timeslot = test_pre_state.into_timeslot()?;

        //
        // State Transitions
        //

        // Timeslot Transition
        let timeslot_context = TimeslotContext {
            header_timeslot: Timeslot::new(test_input.slot),
        };
        timeslot.to_next(&timeslot_context)?;

        // Determine if this transition introduces a new epoch
        let is_new_epoch = timeslot.epoch() > (test_pre_state.tau / EPOCH_LENGTH as u32);

        // EntropyAccumulator Transition
        let entropy_context = EntropyAccumulatorContext {
            timeslot: Timeslot::new(test_input.slot),
            is_new_epoch,
            entropy_hash: test_input.entropy.0,
        };
        entropy_acc.to_next(&entropy_context)?;

        //  PastValidatorSet Transition
        let past_set_context = PastValidatorSetContext {
            timeslot: Timeslot::new(test_input.slot),
            is_new_epoch,
            current_active_set: active_set,
        };
        past_set.to_next(&past_set_context)?;

        //  ActiveValidatorSet Transition
        let active_set_context = ActiveValidatorSetContext {
            timeslot: Timeslot::new(test_input.slot),
            is_new_epoch,
            current_pending_validator_set: safrole_state.pending_validator_set,
        };
        active_set.to_next(&active_set_context)?;

        // Safrole Transition
        let safrole_context = SafroleStateContext {
            timeslot: Timeslot::new(test_input.slot),
            is_new_epoch,
            tickets: test_input
                .extrinsic
                .into_iter()
                .map(TicketEnvelope::into)
                .collect(),
            current_staging_set: staging_set,
            post_active_set: active_set,
            post_entropy: entropy_acc,
        };
        safrole_state.to_next(&safrole_context)?;

        //  StagingValidatorSet Transition
        let staging_set_context = StagingValidatorSetContext {
            timeslot: Timeslot::new(test_input.slot),
            is_new_epoch,
        };
        staging_set.to_next(&staging_set_context)?;

        //
        // Conversion: Jam post-state => Test vector post-state
        //

        let builder = StateBuilder::new();
        let post_state = builder
            .from_safrole_state(&safrole_state)?
            .from_validator_sets(&staging_set, &active_set, &past_set)?
            .from_entropy_accumulator(&entropy_acc)?
            .from_timeslot(&timeslot)?
            .build()?;

        Ok(post_state)
    }

    fn run_state_transition_with_output(
        test_input: Input,
        test_pre_state: State,
    ) -> Result<(State, Output), Box<dyn Error>> {
        match run_state_transition(test_input, test_pre_state.clone()) {
            Ok(state) => Ok((state, Output::ok(OutputMarks::default()))),
            Err(e) => Ok((test_pre_state, Output::err(map_error_to_custom_code(e)))), // represents rollback mechanism for state transition failures
        }
    }

    fn run_test_case(path: &'static str) -> Result<(), Box<dyn Error>> {
        let test_case = load_test_case(path).expect("Failed to load test vector");
        let test_post_state = test_case.post_state; // The expected post state

        let (post_state, _output) =
            run_state_transition_with_output(test_case.input, test_case.pre_state)?;

        // Assertion on the post state
        // assert_eq!(post_state, test_post_state);
        assert_eq!(post_state.tau, test_post_state.tau);
        assert_eq!(post_state.eta, test_post_state.eta);
        assert_eq!(post_state.lambda, test_post_state.lambda);
        assert_eq!(post_state.kappa, test_post_state.kappa);
        assert_eq!(post_state.gamma_k, test_post_state.gamma_k);
        assert_eq!(post_state.iota, test_post_state.iota);
        assert_eq!(post_state.gamma_a, test_post_state.gamma_a);
        assert_eq!(post_state.gamma_s, test_post_state.gamma_s);
        assert_eq!(post_state.gamma_z, test_post_state.gamma_z);

        // Assertion on the state transition output
        // println!(">>> output: {:?}", &test_case.output);
        // assert_eq!(_output, test_case.output);

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
        // Progress by one slot.
        // Randomness accumulator is updated.
        test_enact_epoch_change_with_no_tickets_1: "safrole/tiny/enact-epoch-change-with-no-tickets-1.json",

        // Progress from slot X to slot X.
        // Fail: Timeslot must be strictly monotonic.
        test_enact_epoch_change_with_no_tickets_2: "safrole/tiny/enact-epoch-change-with-no-tickets-2.json",

        // Progress from a slot at the begin of the epoch to a slot in the epoch's tail.
        // Tickets mark is not generated (no enough tickets).
        test_enact_epoch_change_with_no_tickets_3: "safrole/tiny/enact-epoch-change-with-no-tickets-3.json",

        // Progress from epoch's tail to next epoch.
        // Authorities and entropies are rotated.
        // Epoch mark is generated.
        test_enact_epoch_change_with_no_tickets_4: "safrole/tiny/enact-epoch-change-with-no-tickets-4.json",

        // FIXME
        // Progress skipping epochs with a full tickets accumulator.
        // Tickets mark is not generated.
        // Accumulated tickets are discarded.
        // Fallback method is enacted.
        // skip_epochs_1: "safrole/tiny/skip-epochs-1.json",

        // Progress to next epoch by skipping epochs tail with a full tickets accumulator.
        // Tickets mark has no chance to be generated.
        // Accumulated tickets are discarded.
        // Fallback method is enacted.
        skip_epoch_tail_1: "safrole/tiny/skip-epoch-tail-1.json",

        // Fail: Submit an extrinsic with a bad ticket attempt number.
        // publish_tickets_no_mark_1: "safrole/tiny/publish-tickets-no-mark-1.json",

        // Submit good tickets extrinsics from some authorities.
        publish_tickets_no_mark_2: "safrole/tiny/publish-tickets-no-mark-2.json",

        // Fail: Re-submit one ticket already in the state.
        publish_tickets_no_mark_3: "safrole/tiny/publish-tickets-no-mark-3.json",

        // Fail: Submit tickets in bad order.
        publish_tickets_no_mark_4: "safrole/tiny/publish-tickets-no-mark-4.json",

        // FIXME
        // Fail: Submit tickets with bad ring proof.
        // publish_tickets_no_mark_5: "safrole/tiny/publish-tickets-no-mark-5.json",

        // Submit some tickets.
        publish_tickets_no_mark_6: "safrole/tiny/publish-tickets-no-mark-6.json",

        // FIXME
        // Fail: Submit tickets while in epoch's tail.
        // publish_tickets_no_mark_7: "safrole/tiny/publish-tickets-no-mark-7.json",

        // Progress into epoch tail.
        // No enough tickets, thus no tickets mark is generated.
        publish_tickets_no_mark_8: "safrole/tiny/publish-tickets-no-mark-8.json",

        // Progress into next epoch with no enough tickets.
        // Accumulated tickets are discarded.
        // Epoch mark is generated.
        // Fallback method is enacted.
        publish_tickets_no_mark_9: "safrole/tiny/publish-tickets-no-mark-9.json",

        // Publish some tickets with an almost full tickets accumulator.
        // Tickets accumulator is not full yet.
        // No ticket are dropped from accumulator.
        publish_tickets_with_mark_1: "safrole/tiny/publish-tickets-with-mark-1.json",

        // FIXME
        // Publish some more tickets.
        // Tickets accumulator is filled.
        // Two old ticket are removed from the accumulator.
        // publish_tickets_with_mark_2: "safrole/tiny/publish-tickets-with-mark-2.json",

        // FIXME
        // Publish some more tickets.
        // Accumulator is full before execution.
        // Some old ticket are removed to make space for new ones.
        // publish_tickets_with_mark_3: "safrole/tiny/publish-tickets-with-mark-3.json",

        // Progress into epoch tail.
        // Tickets mark is generated.
        publish_tickets_with_mark_4: "safrole/tiny/publish-tickets-with-mark-4.json",

        // FIXME
        // Progress into next epoch.
        // Epoch mark is generated.
        // Tickets are enacted.
        // publish_tickets_with_mark_5: "safrole/tiny/publish-tickets-with-mark-5.json",
    }
}
