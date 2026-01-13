use std::{env, fs, fs::ReadDir, path::PathBuf};

/// Build script to generate test cases from JSON test vectors
fn main() {
    // PVM test cases
    generate_pvm_tests();
    // Block import test cases
    generate_block_import_tests();
    // Fuzzer Block import test cases
    generate_fuzzer_block_import_tests();
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

/// Runs block import tests using simple block import harness (no forks)
fn generate_block_import_tests() {
    let test_vectors_dir = PathBuf::from("jamtestvectors-polkajam/traces");
    let full_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(test_vectors_dir);
    println!("cargo:rerun-if-changed={}", full_path.display());

    let dest_path =
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_block_import_tests.rs");

    let mut test_case_contents =
        String::from("use fr_test_utils::importer_harness::run_test_case;");

    let block_import_groups = [
        "fallback",
        "safrole",
        "preimages",
        "preimages_light",
        "storage",
        "storage_light",
    ];

    for group in block_import_groups {
        let dir_path = full_path.join(group);
        let test_files = fs::read_dir(&dir_path).unwrap_or_else(|_| {
            panic!("Failed to read {group} test vectors dir");
        });
        write_block_import_test_cases(test_files, group, &mut test_case_contents);
    }

    fs::write(&dest_path, test_case_contents).expect("Failed to generate test cases");
}

/// Runs block import tests using fuzzer harness (supports forks)
fn generate_fuzzer_block_import_tests() {
    let fuzz_traces_dir = PathBuf::from("jam-conformance/fuzz-reports/0.7.2/traces");
    let fuzz_traces_full_path =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(fuzz_traces_dir);
    println!("cargo:rerun-if-changed={}", fuzz_traces_full_path.display());

    let dest_path =
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_fuzzer_block_import_tests.rs");

    let mut test_case_contents = String::from("use fr_fuzz::fuzzer::run_fuzz_trace_dir;");

    let mut write_fuzzer_case = |test_name: &str, trace_path: &PathBuf| {
        let trace_path_str = trace_path.to_str().unwrap();
        test_case_contents.push_str(&format!(
            "\
            #[tokio::test]\
            async fn {test_name}() -> Result<(), Box<dyn std::error::Error>> {{
                run_fuzz_trace_dir(\"{trace_path_str}\").await?;
                Ok(())
            }}"
        ));
    };

    let trace_dirs = fs::read_dir(&fuzz_traces_full_path).expect("Failed to read fuzz trace dir");
    let mut trace_paths: Vec<PathBuf> = trace_dirs
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    trace_paths.sort();

    for trace_path in trace_paths {
        let trace_name = match trace_path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };
        let test_name = format!("block_import_conformance_0_7_2_{}", trace_name);
        write_fuzzer_case(&test_name, &trace_path);
    }

    let fuzzy_block_groups = ["fuzzy", "fuzzy_light"];

    for group in fuzzy_block_groups {
        let trace_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .join(format!("jamtestvectors-polkajam/traces/{group}"));
        println!("cargo:rerun-if-changed={}", trace_path.display());

        if trace_path.is_dir() {
            let test_name = format!("block_import_{group}_all");
            write_fuzzer_case(&test_name, &trace_path);
        }
    }

    fs::write(&dest_path, test_case_contents).expect("Failed to generate test cases");
}
