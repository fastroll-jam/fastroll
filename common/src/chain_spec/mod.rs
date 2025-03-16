cfg_if::cfg_if! {
    if #[cfg(feature = "tiny")] {
        mod tiny;
        pub use tiny::*;
    } else if #[cfg(feature = "small")] {
        mod small;
        pub use small::*;
    } else {
        mod full;
        pub use full::*;
    }
}
