use criterion::{criterion_group, criterion_main, Criterion};
use fr_clock::{TimeProvider, UnixTimeProvider};
use fr_fuzz::fuzzer::{run_fuzz_trace_dir_with_timings, FuzzImportTiming};
use std::{
    env,
    fs::{create_dir_all, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::runtime::Runtime;

const TRACES_PATH: &str = "../integration/jamtestvectors-polkajam/traces";
const BENCH_GROUP_NAME: &str = "block_import_fuzz_per_block";
const DEFAULT_SAMPLE_SIZE: usize = 30;
const DEFAULT_MEASUREMENT_TIME: Duration = Duration::from_secs(10);

fn resolve_trace_dir() -> PathBuf {
    let trace_kind = env::var("TRACE_KIND")
        .or_else(|_| env::var("KIND"))
        .unwrap_or_else(|_| "storage".to_string());
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join(TRACES_PATH)
        .join(trace_kind)
}

fn format_case_label(timing: &FuzzImportTiming) -> String {
    timing
        .path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("case")
        .to_string()
}

fn bench_report_dir() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("reports")
}

fn create_bench_report_file(trace_label: &str, report_dir: &Path) -> (File, u64) {
    create_dir_all(report_dir).expect("Failed to create bench report directory");
    let unix_timestamp = TimeProvider::now_unix_timestamp();
    let report_path = report_dir.join(format!("{trace_label}_{unix_timestamp}.log"));

    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)
    {
        Ok(file) => (file, unix_timestamp),
        Err(err) => panic!("Failed to create bench report file: {err}"),
    }
}

fn write_bench_report(
    report_dir: &Path,
    trace_label: &str,
    total_iters: u64,
    block_labels: &[String],
    per_block_totals: &[Duration],
    suite_total: Duration,
) {
    let (mut file, timestamp) = create_bench_report_file(trace_label, report_dir);

    let denom = total_iters as f64;
    let suite_avg_ms = suite_total.as_secs_f64() * 1000.0 / denom;

    writeln!(
        file,
        "timestamp={} trace_label={} total_iters={} blocks={}",
        timestamp,
        trace_label,
        total_iters,
        block_labels.len()
    )
    .expect("Failed to write bench report header");

    writeln!(file, "total_avg_ms={:.3}", suite_avg_ms)
        .expect("Failed to write bench report suite average");

    writeln!(file, "per_block_avg_ms:").expect("Failed to write bench report block header");
    for (label, total) in block_labels.iter().zip(per_block_totals.iter()) {
        let avg_ms = total.as_secs_f64() * 1000.0 / denom;
        writeln!(file, "{:>8} {:.3}", label, avg_ms).expect("Failed to write bench report");
    }

    writeln!(file, "----").expect("Failed to write bench report");
}

/// Aggregates per-sample timing totals across Criterion iterations.
#[derive(Default)]
struct BenchAggregate {
    total_iters: u64,
    per_block_totals: Vec<Duration>,
    block_labels: Vec<String>,
    suite_total: Duration,
}

impl BenchAggregate {
    fn add_sample(
        &mut self,
        iters: u64,
        block_labels: &[String],
        per_block_totals: &[Duration],
        suite_total: Duration,
    ) {
        if self.per_block_totals.is_empty() {
            self.per_block_totals = vec![Duration::ZERO; per_block_totals.len()];
            self.block_labels = block_labels.to_vec();
        } else if self.per_block_totals.len() != per_block_totals.len() {
            panic!("Trace case count changed between iterations");
        }

        for (idx, total) in per_block_totals.iter().enumerate() {
            self.per_block_totals[idx] += *total;
        }
        self.suite_total += suite_total;
        self.total_iters += iters;
    }
}

fn bench_block_import(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group(BENCH_GROUP_NAME);

    let trace_dir = resolve_trace_dir();
    if !trace_dir.is_dir() {
        panic!("Trace directory does not exist: {}", trace_dir.display());
    }
    let trace_dir_str = trace_dir
        .to_str()
        .expect("Invalid trace directory path")
        .to_string();
    let trace_label = trace_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("Invalid file name")
        .to_string();

    let mut aggregate = BenchAggregate::default();
    let bench_id = format!("import-bench-{trace_label}");
    group.bench_function(bench_id, |b| {
        let trace_dir_str = trace_dir_str.clone();
        b.iter_custom(|iters| {
            let iters = iters.max(1);
            let mut per_block_totals = vec![];
            let mut block_labels = vec![];

            let total = rt.block_on(async {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let timings = run_fuzz_trace_dir_with_timings(&trace_dir_str)
                        .await
                        .unwrap_or_else(|e| panic!("Fuzz trace failed: {e:?}"));
                    if timings.is_empty() {
                        panic!("No import cases found in {trace_dir_str}");
                    }
                    if per_block_totals.is_empty() {
                        per_block_totals = vec![Duration::ZERO; timings.len()];
                        block_labels = timings.iter().map(format_case_label).collect();
                    }
                    if timings.len() != per_block_totals.len() {
                        panic!("Trace case count changed between iterations");
                    }
                    for (idx, timing) in timings.iter().enumerate() {
                        per_block_totals[idx] += timing.duration;
                        total += timing.duration;
                    }
                }
                total
            });

            aggregate.add_sample(iters, &block_labels, &per_block_totals, total);
            total
        });
    });

    group.finish();

    if aggregate.total_iters > 0 {
        write_bench_report(
            &bench_report_dir(),
            &trace_label,
            aggregate.total_iters,
            &aggregate.block_labels,
            &aggregate.per_block_totals,
            aggregate.suite_total,
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(DEFAULT_SAMPLE_SIZE)
        .measurement_time(DEFAULT_MEASUREMENT_TIME)
        .configure_from_args();
    targets = bench_block_import
}
criterion_main!(benches);
