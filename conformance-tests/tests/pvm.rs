//! PVM instruction conformance tests
// mod all_tests {
//     use rjam_conformance_tests::pvm_harness::run_test_case;
//     include!(concat!(env!("OUT_DIR"), "/generated_pvm_tests.rs"));
// }

mod tests {
    use rjam_conformance_tests::generate_pvm_tests;

    generate_pvm_tests! {
        gas_basic_consume_all: "gas_basic_consume_all.json",
    }
}
