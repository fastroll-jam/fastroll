cfg_if::cfg_if! {
    if #[cfg(feature = "tiny")] {
        mod tiny;
        pub use tiny::*;
    } else {
        mod full;
        pub use full::*;
    }
}
