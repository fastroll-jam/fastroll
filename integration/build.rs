use std::{env, fs, fs::ReadDir, path::PathBuf};

/// Build script to generate test cases from JSON test vectors
fn main() {
    // PVM test cases
    generate_pvm_tests();
    // Block import test cases
    generate_block_import_tests();
    // Block import test cases (fuzz traces)
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
        "1761552708",
        "1761552851",
        "1761553047",
        "1761553072",
        "1761553157",
        "1761553506",
        "1761553554",
        "1761650152",
        "1761650657",
        "1761651476",
        "1761651616",
        "1761651767",
        "1761651837",
        "1761652427",
        "1761652768",
        "1761653013",
        "1761653121",
        "1761653246",
        "1761654464",
        "1761654584",
        "1761654684",
        "1761655910",
        "1761656086",
        "1761661472",
        "1761661586",
        "1761662449",
        "1761662834",
        "1761663151",
        "1761663633",
        "1761663744",
        "1761663992",
        "1761664166",
        "1761664407",
        "1761664779",
        "1761665051",
        "1761665268",
        "1761665434",
        "1761665520",
        "1761666724",
        "1761667005",
        "1761667093",
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
