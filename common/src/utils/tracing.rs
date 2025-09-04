use std::sync::Once;
use time::{macros::format_description, UtcOffset};
use tracing::subscriber::set_global_default;
use tracing_subscriber::{
    fmt,
    fmt::{format::FmtSpan, time::OffsetTime},
    prelude::*,
    EnvFilter, Registry,
};

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
        set_global_default(sub).expect("Failed to set tracing subscriber");
    });
}

pub fn setup_tracing() {
    static INIT_TRACING: Once = Once::new();
    INIT_TRACING.call_once(|| {
        let offset = UtcOffset::current_local_offset().expect("Should get local offset");
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
        set_global_default(sub).expect("Failed to set tracing subscriber");
    })
}
