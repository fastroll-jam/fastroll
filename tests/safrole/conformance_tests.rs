#[cfg(test)]
mod tests {
    use crate::safrole::{asn_types::Testcase, utils::StateBuilder};
    use rjam::{
        state::components::timeslot::Timeslot,
        transition::{SlotType, Transition, TransitionContext},
    };
    use std::{error::Error, fs};

    // Safrole state transition conformance tests

    fn load_test_case(path: &'static str) -> Result<Testcase, ()> {
        let json_str = fs::read_to_string(&path).expect("Failed to read test vector file");
        let test_case = serde_json::from_str(&json_str).expect("Failed to parse JSON");
        Ok(test_case)
    }

    #[test]
    fn test_enact_epoch_change_with_no_tickets_4() -> Result<(), Box<dyn Error>> {
        let test_case = load_test_case(
            "../jamtestvectors/safrole/tiny/enact-epoch-change-with-no-tickets-4.json",
        )
        .expect("Failed to load test case");

        // Conversion: Test vector pre-state => Jam pre-state
        let test_state = test_case.pre_state;
        let pre_safrole = test_state.into_safrole_state()?;
        let (pre_staging_set, pre_active_set, pre_past_set) = test_state.into_validator_sets()?;
        let pre_entropy_acc = test_state.into_entropy_accumulator()?;
        let pre_timeslot = test_state.into_timeslot()?;

        // println!(">>> Pre State <<<");
        // println!(">>> Safrole: {}", &pre_safrole);
        // println!(">>> Staging Set: {}", &pre_staging_set);
        // println!(">>> Active Set: {}", &pre_active_set);
        // println!(">>> Past Set: {}", &pre_past_set);
        // println!(">>> Entropy Acc: {}", &pre_entropy_acc);

        // State Transitions
        let context_input = test_case.input;
        let context = TransitionContext {
            timeslot: Timeslot(0),
            slot_type: SlotType::NewEpoch,
        };
        let post_safrole = pre_safrole.next(&context)?;
        let post_staging_set = pre_staging_set.next(&context)?;
        let post_active_set = pre_active_set.next(&context)?;
        let post_past_set = pre_past_set.next(&context)?;
        let post_entropy_acc = pre_entropy_acc.next(&context)?;
        let post_timeslot = pre_timeslot.next(&context)?;

        // Conversion: Jam post-state => Test vector post-state
        let builder = StateBuilder::new();
        let post_test_state = builder
            .from_safrole_state(&post_safrole)?
            .from_validator_sets(&post_staging_set, &post_active_set, &post_past_set)?
            .from_entropy_accumulator(&post_entropy_acc)?
            .from_timeslot(&post_timeslot)?
            .build()?;
        let output = ();

        // assert_eq!(post_test_state, test_case.post_state);
        Ok(())
    }
}
