//! Block importer integration tests
#[cfg(feature = "tiny")]
mod block_importer_all {
    include!(concat!(env!("OUT_DIR"), "/generated_block_import_tests.rs"));
    include!(concat!(
        env!("OUT_DIR"),
        "/generated_fuzzer_block_import_tests.rs"
    ));
}
