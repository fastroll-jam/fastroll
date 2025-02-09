//! PVM instruction conformance tests
mod all_tests {
    include!(concat!(env!("OUT_DIR"), "/generated_pvm_tests.rs"));
}
