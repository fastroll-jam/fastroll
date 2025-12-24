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
        "1766241814",
        "1766241867",
        "1766241968",
        "1766242478",
        "1766242569",
        "1766242639",
        "1766242660",
        "1766243113",
        "1766243147",
        "1766243176",
        "1766243315_1733",
        "1766243315_2078",
        "1766243315_2277",
        "1766243315_3530",
        "1766243315_6968",
        "1766243315_7092",
        "1766243315_7231",
        "1766243315_7763",
        "1766243315_8065",
        "1766243315_9206",
        "1766243315_9273",
        "1766243493_1016",
        "1766243493_1163",
        "1766243493_2605",
        "1766243493_2637",
        "1766243493_2882",
        "1766243493_5192",
        "1766243493_6113",
        "1766243493_8886",
        "1766243493_9727",
        "1766243493_9922",
        "1766243774_5938",
        "1766243774_6746",
        "1766243861_2056",
        "1766243861_2612",
        "1766243861_5589",
        "1766243861_7039",
        "1766243861_7323",
        "1766243861_7767",
        "1766243861_8319",
        "1766243861_8838",
        "1766243861_8892",
        "1766243861_9909",
        "1766244033_5444",
        "1766244122_3342",
        "1766244122_3401",
        "1766244122_3562",
        "1766244122_5414",
        "1766244122_5900",
        "1766244122_6899",
        "1766244122_6938",
        "1766244122_7675",
        "1766244122_8730",
        "1766244122_9726",
        "1766244251_1055",
        "1766244251_1244",
        "1766244251_1816",
        "1766244251_2288",
        "1766244251_2939",
        "1766244251_4514",
        "1766244251_5231",
        "1766244251_5493",
        "1766244251_6558",
        "1766244251_9568",
        "1766244556_3963",
        "1766244556_4989",
        "1766244556_6133",
        "1766255635_1584",
        "1766255635_2170",
        "1766255635_2557",
        "1766255635_3335",
        "1766255635_3673",
        "1766255635_3689",
        "1766255635_4398",
        "1766255635_7054",
        "1766255635_7229",
        "1766255777_4629",
        "1766255777_6480",
        "1766255777_8627",
        "1766255961_5132",
        "1766256032_8838",
        "1766256151_4088",
        "1766256151_5250",
        "1766256151_9235",
        "1766479507_1044",
        "1766479507_1854",
        "1766479507_2200",
        "1766479507_3250",
        "1766479507_3537",
        "1766479507_4840",
        "1766479507_5115",
        "1766479507_5629",
        "1766479507_6078",
        "1766479507_6139",
        "1766479507_7090",
        "1766479507_7734",
        "1766479507_7943",
        "1766479507_8988",
        "1766479507_9966",
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
