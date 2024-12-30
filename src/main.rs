use rjam_common::{Hash32, HASH32_EMPTY};
use rjam_db::{BlockHeaderDB, RocksDBConfig, StateDB};
use rjam_extrinsics::pool::EXTRINSICS_POOL;
use rjam_state::StateManager;
use rjam_state_merkle::merkle_db::MerkleDB;
use rjam_types::block::Block;
use std::{path::PathBuf, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Explicitly initialize the extrinsics pool
    lazy_static::initialize(&EXTRINSICS_POOL);
    println!("extrinsic pool initialized successfully");

    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    const HEADER_DB_CACHE_SIZE: usize = 1000;

    let state_db_config = RocksDBConfig::from_path(PathBuf::from("./.rocksdb/state"));
    let header_db_config = RocksDBConfig::from_path(PathBuf::from("./.rocksdb/header"));
    let merkle_db_config = RocksDBConfig::from_path(PathBuf::from("./.rocksdb/merkle"));

    let merkle_db = MerkleDB::open(&merkle_db_config, MERKLE_DB_CACHE_SIZE)?;
    let state_db = StateDB::open(&state_db_config)?;
    let _state_manager = StateManager::new(Arc::new(state_db), Arc::new(merkle_db));
    let mut header_db = BlockHeaderDB::open(&header_db_config, HEADER_DB_CACHE_SIZE)?;

    println!("DB initialized successfully");

    header_db.init_staging_header(HASH32_EMPTY)?;
    header_db.update_staging_header(|header| {
        header.timeslot_index = 1;
    })?;
    header_db.commit_staging_header()?;

    let header_1 = header_db.get_header(1)?;
    println!("Header 1:");
    println!("{}", header_1);

    Ok(())
}

#[allow(dead_code)]
fn validate_block(
    _state_manager: &StateManager,
    _block: &Block,
    _posterior_state_root: &Hash32,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}
