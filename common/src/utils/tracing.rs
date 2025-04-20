use tracing::subscriber::set_global_default;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

pub fn setup_timed_tracing() {
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_timer(fmt::time::uptime());
    let sub = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt_layer);
    set_global_default(sub).expect("Failed to set tracing subscriber");
}
