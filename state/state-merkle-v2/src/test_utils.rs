use crate::merkle_db::MerkleDB;
use fr_config::{StorageConfig, MERKLE_CF_NAME, MERKLE_LEAF_PATHS_CF_NAME};
use fr_db::core::core_db::CoreDB;
use std::sync::Arc;
use tempfile::tempdir;

fn open_core_db() -> CoreDB {
    let db_path = tempdir().unwrap().path().join("test_db");
    CoreDB::open(
        db_path,
        StorageConfig::rocksdb_opts(),
        StorageConfig::cf_descriptors(),
    )
    .unwrap()
}

pub(crate) fn open_merkle_db() -> MerkleDB {
    let core_db = open_core_db();
    MerkleDB::new(
        Arc::new(core_db),
        MERKLE_CF_NAME,
        MERKLE_LEAF_PATHS_CF_NAME,
        4096,
    )
}
