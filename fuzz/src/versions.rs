pub const FUZZ_PROTO_VERSION: u8 = 1;
pub const FUZZ_FEATURES: u32 = 0b11; // "ancestors" & "forking" features enabled
pub const FUZZ_FEATURES_LOCAL_TEST: u32 = 0b10; // only "forking" feature enabled for local test runs (ancestry set not available without original block generator)
