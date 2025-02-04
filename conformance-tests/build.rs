use std::{env, fs, path::PathBuf};

/// Build script to generate PVM test cases from JSON test vectors
fn main() {
    let test_vectors_dir = PathBuf::from("jamtestvectors-pvm/pvm/programs");
    let full_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(test_vectors_dir);
    println!("cargo:rerun-if-changed={}", full_path.display());
    let dest_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("generated_pvm_tests.rs");
    let test_files = fs::read_dir(&full_path).expect("Failed to read test vectors dir");

    let mut test_case_contents = String::new();
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
