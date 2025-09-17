use std::{env, fs, fs::ReadDir, path::PathBuf};

/// Build script to generate test cases from JSON test vectors
fn main() {
    // PVM test cases
    generate_pvm_tests();
    // Block import test cases
    generate_block_import_tests();
    // Fuzzer block import test cases
    generate_fuzz_block_import_tests();
}

fn generate_pvm_tests() {
    let test_vectors_dir = PathBuf::from("jamtestvectors-pvm/pvm/programs");
    let full_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(test_vectors_dir);
    println!("cargo:rerun-if-changed={}", full_path.display());
    let dest_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_pvm_tests.rs");
    let test_files = fs::read_dir(&full_path).expect("Failed to read test vectors dir");

    let mut test_case_contents = String::from("use fr_test_utils::pvm_harness::run_test_case;");

    for test_file in test_files {
        let test_file_path = test_file.expect("Failed to get test file").path();
        let test_file_name = test_file_path.file_name().unwrap().to_str().unwrap();
        let test_name = test_file_name.trim_end_matches(".json");
        test_case_contents.push_str(&format!(
            "\
            #[test]\
            fn pvm_{test_name}() {{
                run_test_case(\"{test_file_name}\")
            }}"
        ));
    }
    fs::write(&dest_path, test_case_contents).expect("Failed to generate test cases");
}

fn write_block_import_test_cases(
    test_files_dir: ReadDir,
    test_group: &str,
    test_case_contents: &mut String,
) {
    for test_file in test_files_dir {
        let test_file_path = test_file.expect("Failed to get test file").path();
        let test_file_path_str = test_file_path.to_str().unwrap();
        let test_file_name = test_file_path.file_name().unwrap().to_str().unwrap();
        if test_file_name.ends_with(".bin") {
            continue;
        }
        if test_file_name.ends_with("genesis.json") {
            continue;
        }
        let test_name = test_file_name.trim_end_matches(".json");
        test_case_contents.push_str(&format!(
            "\
            #[tokio::test]\
            async fn block_import_{test_group}_{test_name}() -> Result<(), Box<dyn std::error::Error>> {{
                run_test_case(\"{test_file_path_str}\").await?;
                Ok(())
            }}"
        ));
    }
}

#[allow(dead_code)]
fn generate_block_import_tests() {
    let test_vectors_dir = PathBuf::from("jamtestvectors-polkajam/traces");
    let full_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(test_vectors_dir);
    println!("cargo:rerun-if-changed={}", full_path.display());

    let fallback_test_files =
        fs::read_dir(full_path.join("fallback")).expect("Failed to read fallback test vectors dir");
    let safrole_test_files =
        fs::read_dir(full_path.join("safrole")).expect("Failed to read safrole test vectors dir");
    let preimages_test_files = fs::read_dir(full_path.join("preimages"))
        .expect("Failed to read preimages test vectors dir");
    let preimages_light_test_files = fs::read_dir(full_path.join("preimages_light"))
        .expect("Failed to read preimages_light test vectors dir");
    let storage_test_files =
        fs::read_dir(full_path.join("storage")).expect("Failed to read storage test vectors dir");
    let storage_light_test_files = fs::read_dir(full_path.join("storage_light"))
        .expect("Failed to read storage_light test vectors dir");

    let dest_path =
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_block_import_tests.rs");

    let mut test_case_contents =
        String::from("use fr_test_utils::importer_harness::run_test_case;");

    write_block_import_test_cases(fallback_test_files, "fallback", &mut test_case_contents);
    write_block_import_test_cases(safrole_test_files, "safrole", &mut test_case_contents);
    write_block_import_test_cases(preimages_test_files, "preimages", &mut test_case_contents);
    write_block_import_test_cases(
        preimages_light_test_files,
        "preimages_light",
        &mut test_case_contents,
    );
    write_block_import_test_cases(storage_test_files, "storage", &mut test_case_contents);
    write_block_import_test_cases(
        storage_light_test_files,
        "storage_light",
        &mut test_case_contents,
    );

    fs::write(&dest_path, test_case_contents).expect("Failed to generate test cases");
}

fn generate_fuzz_block_import_tests() {
    let test_vectors_dir = PathBuf::from("fuzz-traces");
    let full_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(test_vectors_dir);
    println!("cargo:rerun-if-changed={}", full_path.display());

    let traces_folders = [
        // "1756548459",
        // "1756548583",
        // "1756548667",
        // "1756548706",
        // "1756548741",
        // "1756548767",
        // "1756548796",
        // "1756548916",
        // "1756572122",
        // "1756790723",
        // "1756791458",
        // "1756792661",
        // "1756814312",
        // "1756832925",
        // ----- New reports batch
        "1757406079",
        "1757406238",
        "1757406356",
        "1757406441",
        "1757406516",
        "1757406558",
        "1757406598",
        "1757421101",
        "1757421743",
        "1757421824",
        "1757421952",
        "1757422106",
        "1757422178",
        "1757422206",
        "1757422550",
        "1757422647",
        "1757422771", // fail-on-fuzz [FORKING]
        "1757423102", // fail-on-fuzz [FORKING]
        "1757423195",
        "1757423271",
        "1757423365", // fail-on-fuzz [FORKING]
        "1757423433",
        "1757423902", // fail [FORKING] (success-on-fuzz)
        "1757841566",
        "1757842797",
        "1757842852",
        "1757843609",
        "1757843719",
        "1757843735",
        "1757861618",
        "1757862207",
        "1757862468", // fail (memory access violation)
        "1757862472", // fail (memory access violation)
        "1757862743",
    ];

    let mut test_case_contents = String::new();
    for traces_folder in traces_folders {
        let test_file =
            fs::read_dir(full_path.join(traces_folder)).expect("Failed to read trace folder");
        write_block_import_test_cases(test_file, traces_folder, &mut test_case_contents);
    }

    let dest_path =
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_fuzz_block_import_tests.rs");
    fs::write(&dest_path, test_case_contents).expect("Failed to generate test cases");
}
