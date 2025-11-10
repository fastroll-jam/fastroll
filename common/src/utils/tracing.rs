#[cfg(feature = "flamegraph")]
use std::path::Path;
use std::sync::Once;
use time::{macros::format_description, UtcOffset};
use tracing::subscriber::set_global_default;
#[cfg(feature = "flamegraph")]
use tracing_flame::FlameLayer;
use tracing_subscriber::{
    fmt,
    fmt::{format::FmtSpan, time::OffsetTime},
    prelude::*,
    EnvFilter, Registry,
};

// Note: test-only
#[cfg(feature = "flamegraph")]
pub fn setup_timed_tracing_with_flamegraph(path: &str) {
    let path = Path::new(path);
    let file_stem = path.file_stem().unwrap().to_str().unwrap();
    let test_kind = path
        .parent()
        .and_then(|p| p.file_name())
        .unwrap()
        .to_str()
        .unwrap();
    let flame_output_path = format!("./target/{test_kind}-{file_stem}.folded");
    static INIT_TIMED_TRACING: Once = Once::new();
    INIT_TIMED_TRACING.call_once(|| {
        let fmt_layer = fmt::layer()
            .with_target(false)
            .with_timer(fmt::time::uptime())
            .with_span_events(FmtSpan::CLOSE);
        let (flame_layer, _guard) = FlameLayer::with_file(flame_output_path).unwrap();
        let sub = Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt_layer)
            .with(flame_layer);
        set_global_default(sub).expect("Failed to set tracing subscriber");
    });
}

pub fn setup_timed_tracing() {
    static INIT_TIMED_TRACING: Once = Once::new();
    INIT_TIMED_TRACING.call_once(|| {
        let fmt_layer = fmt::layer()
            .with_target(false)
            .with_timer(fmt::time::uptime())
            .with_span_events(FmtSpan::CLOSE);
        let sub = Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt_layer);
        if let Err(e) = set_global_default(sub) {
            tracing::warn!("Failed to set tracing subscriber: {e}");
        }
    });
}

pub fn setup_tracing() {
    static INIT_TRACING: Once = Once::new();
    INIT_TRACING.call_once(|| {
        let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
        let timer = OffsetTime::new(
            offset,
            format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:2]"
            ),
        );
        let fmt_layer = fmt::layer().with_target(false).with_timer(timer);
        let sub = Registry::default()
            .with(EnvFilter::from_default_env())
            .with(fmt_layer);
        if let Err(e) = set_global_default(sub) {
            tracing::warn!("Failed to set tracing subscriber: {e}");
        }
    })
}
