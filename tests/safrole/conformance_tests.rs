#[cfg(test)]
mod tests {
    use crate::safrole::{
        asn_types::{Testcase, TicketEnvelope, EPOCH_LENGTH},
        utils::StateBuilder,
    };
    use rjam::{
        state::components::{
            entropy::EntropyAccumulatorContext,
            safrole::SafroleStateContext,
            timeslot::{Timeslot, TimeslotContext},
            validators::{
                ActiveValidatorSetContext, PastValidatorSetContext, StagingValidatorSetContext,
            },
        },
        transition::Transition,
    };
    use std::{error::Error, fmt::Debug, fs};
    // Safrole state transition conformance tests

    fn load_test_case(path: &'static str) -> Result<Testcase, ()> {
        let json_str = fs::read_to_string(&path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_case)
    }

    fn run_test_case(path: &'static str) -> Result<(), Box<dyn Error>> {
        let test_case = load_test_case(path).expect("Failed to load test vector");

        //
        // Conversion: Test vector pre-state => Jam pre-state
        //

        let test_pre_state = test_case.pre_state;
        let mut safrole_state = test_pre_state.into_safrole_state()?;
        let (mut staging_set, mut active_set, mut past_set) =
            test_pre_state.into_validator_sets()?;
        let mut entropy_acc = test_pre_state.into_entropy_accumulator()?;
        let mut timeslot = test_pre_state.into_timeslot()?;

        //
        // State Transitions
        //

        let test_input = test_case.input;

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
        let output = ();

        let test_post_state = test_case.post_state;

        //
        // Assertions
        //

        assert_eq!(post_state, test_post_state);

        // assert_eq!(post_state.tau, test_post_state.tau);
        // assert_eq!(post_state.eta, test_post_state.eta);
        // assert_eq!(post_state.lambda, test_post_state.lambda);
        // assert_eq!(post_state.kappa, test_post_state.kappa);
        // assert_eq!(post_state.gamma_k, test_post_state.gamma_k);
        // assert_eq!(post_state.iota, test_post_state.iota);
        // assert_eq!(post_state.gamma_a, test_post_state.gamma_a);
        // assert_eq!(post_state.gamma_s, test_post_state.gamma_s);
        // assert_eq!(post_state.gamma_z, test_post_state.gamma_z);

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
        test_enact_epoch_change_with_no_tickets_1: "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-1.json",
        test_enact_epoch_change_with_no_tickets_2: "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-2.json",
        test_enact_epoch_change_with_no_tickets_3: "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-3.json",
        test_enact_epoch_change_with_no_tickets_4: "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-4.json",
        publish_tickets_no_mark_1: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-1.json",
        publish_tickets_no_mark_2: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-2.json",
        publish_tickets_no_mark_3: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-3.json",
        publish_tickets_no_mark_4: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-4.json",
        publish_tickets_no_mark_5: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-5.json",
        publish_tickets_no_mark_6: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-6.json",
        publish_tickets_no_mark_7: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-7.json",
        publish_tickets_no_mark_8: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-8.json",
        publish_tickets_no_mark_9: "../jamtestvectors/safrole/tiny/publish-tickets-no-mark-9.json",
    }
}
