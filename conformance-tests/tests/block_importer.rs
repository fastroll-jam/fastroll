use fr_conformance_tests::importer_harness::run_test_case;
use std::error::Error;

macro_rules! run_block_import_test {
    ($block_num:expr) => {
        paste::paste! {
            #[tokio::test]
            async fn [<block_import_fallback_ $block_num>]() -> Result<(), Box<dyn Error>> {
                let test_file_name = format!("{:08}.json", $block_num);
                run_test_case("jamtestvectors-polkajam/traces/fallback", &test_file_name).await?;
                Ok(())
            }

            #[tokio::test]
            async fn [<block_import_safrole_ $block_num>]() -> Result<(), Box<dyn Error>> {
                let test_file_name = format!("{:08}.json", $block_num);
                run_test_case("jamtestvectors-polkajam/traces/safrole", &test_file_name).await?;
                Ok(())
            }

            // #[tokio::test]
            // async fn [<block_import_reports_ $block_num>]() -> Result<(), Box<dyn Error>> {
            //     let test_file_name = format!("{:08}.json", $block_num);
            //     run_test_case("jamtestvectors-polkajam/traces/reports-l0", &test_file_name).await?;
            //     Ok(())
            // }
        }
    };
}

// run_block_import_test!(0); // FIXME: Import genesis block
run_block_import_test!(1);
run_block_import_test!(2);
run_block_import_test!(3);
run_block_import_test!(4);
run_block_import_test!(5);
run_block_import_test!(6);
run_block_import_test!(7);
run_block_import_test!(8);
run_block_import_test!(9);
run_block_import_test!(10);
run_block_import_test!(11);
run_block_import_test!(12);
run_block_import_test!(13);
run_block_import_test!(14);
run_block_import_test!(15);
run_block_import_test!(16);
run_block_import_test!(17);
run_block_import_test!(18);
run_block_import_test!(19);
run_block_import_test!(20);
run_block_import_test!(21);
run_block_import_test!(22);
run_block_import_test!(23);
run_block_import_test!(24);
run_block_import_test!(25);
run_block_import_test!(26);
run_block_import_test!(27);
run_block_import_test!(28);
run_block_import_test!(29);
run_block_import_test!(30);
run_block_import_test!(31);
run_block_import_test!(32);
run_block_import_test!(33);
run_block_import_test!(34);
run_block_import_test!(35);
run_block_import_test!(36);
run_block_import_test!(37);
run_block_import_test!(38);
run_block_import_test!(39);
run_block_import_test!(40);
run_block_import_test!(41);
run_block_import_test!(42);
