use criterion::{criterion_group, criterion_main, BatchSize, Bencher, Criterion};
use fr_node::roles::importer::BlockImporter;
use fr_state::state_utils::add_all_simple_state_entries;
use fr_storage::node_storage::NodeStorage;
use fr_test_utils::importer_harness::{get_parent_block_header, BlockImportHarness, TestCase};
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::runtime::Runtime;

async fn setup(file_path: &Path) -> (Arc<NodeStorage>, TestCase) {
    // load test case
    let test_case = BlockImportHarness::load_test_case(file_path);
    let test_case = BlockImportHarness::convert_test_case(test_case);

    // init node storage
    let storage = Arc::new(BlockImportHarness::init_node_storage());

    // initialize state keys if genesis block
    if test_case.block.is_genesis() {
        add_all_simple_state_entries(&storage.state_manager(), None)
            .await
            .expect("Failed to initialize simple state entries");
    }

    BlockImportHarness::commit_pre_state(&storage.state_manager(), test_case.pre_state.clone())
        .await
        .expect("Failed to commit pre state");

    if !test_case.block.is_genesis() {
        // Workaround: Import parent block from the previous test case and then set it as best header.
        let parent_header = get_parent_block_header(file_path.to_str().unwrap());
        let parent_header_hash = parent_header
            .hash()
            .expect("Failed to compute parent header hash");
        storage.header_db().set_best_header(parent_header);

        // Set post state root of the parent block (prior state root)
        storage
            .post_state_root_db()
            .set_post_state_root(
                &parent_header_hash,
                test_case.block.header.parent_state_root().clone(),
            )
            .await
            .expect("Failed to set post state root");
    }
    (storage, test_case)
}

fn bench_block_import(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("block_import");
    // group.sample_size(10);

    let test_kind = "storage";
    let test_file = "00000008.json";
    let bench_id = [test_kind, "-", test_file].concat();
    let test_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../integration")
        .join("jamtestvectors-polkajam/traces")
        .join(test_kind)
        .join(test_file);

    group.bench_function(bench_id, |b: &mut Bencher| {
        b.iter_batched(
            // Setup
            || rt.block_on(setup(&test_path)),
            // Routine
            |(storage, test_case)| {
                rt.block_on(async {
                    let _post_state_root = match BlockImporter::import_block(
                        storage.clone(),
                        test_case.block.clone(),
                        false,
                        false,
                    )
                    .await
                    {
                        Ok((post_state_root, _account_state_changes)) => post_state_root,
                        Err(e) => {
                            panic!("Block import failed during benchmarking: {e:?}");
                        }
                    };
                });
            },
            // Size
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_block_import);
criterion_main!(benches);
