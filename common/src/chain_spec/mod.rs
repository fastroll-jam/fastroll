cfg_if::cfg_if! {
    if #[cfg(feature = "full")] {
        mod full;
        pub use full::*;
    } else if #[cfg(feature = "small")] {
        mod small;
        pub use small::*;
    } else {
        mod tiny;
        pub use tiny::*;
    }
}
