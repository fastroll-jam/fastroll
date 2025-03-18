use rocksdb::{ColumnFamilyDescriptor, Options};

pub const STATE_CF_NAME: &str = "state_cf";
pub const MERKLE_CF_NAME: &str = "merkle_cf";
pub const HEADER_CF_NAME: &str = "header_cf";

pub struct RocksDBOpts {
    pub opts: Options,
    pub column_families: Vec<ColumnFamilyDescriptor>,
}

impl Default for RocksDBOpts {
    fn default() -> Self {
        Self {
            opts: Self::rocksdb_opts(),
            column_families: Self::column_family_descriptors(),
        }
    }
}

impl RocksDBOpts {
    fn column_family_descriptors() -> Vec<ColumnFamilyDescriptor> {
        vec![
            ColumnFamilyDescriptor::new(STATE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(MERKLE_CF_NAME, Options::default()),
            ColumnFamilyDescriptor::new(HEADER_CF_NAME, Options::default()),
        ]
    }

    fn rocksdb_opts() -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts
    }
}
