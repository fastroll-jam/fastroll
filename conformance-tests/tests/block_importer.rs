//! Block importer conformance tests
mod block_importer_all {
    include!(concat!(env!("OUT_DIR"), "/generated_block_import_tests.rs"));
    include!(concat!(
        env!("OUT_DIR"),
        "/generated_fuzz_block_import_tests.rs"
    ));
}
