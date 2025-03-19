pub(crate) mod config;
pub(crate) mod timeslot_scheduler;

use rjam_block::header_db::BlockHeaderDB;
use rjam_common::Hash32;
use rjam_db::{
    config::{RocksDBOpts, HEADER_CF_NAME, MERKLE_CF_NAME, STATE_CF_NAME},
    core::core_db::CoreDB,
};
use rjam_extrinsics::pool::XtPool;
use rjam_state::{manager::StateManager, state_db::StateDB};
use rjam_state_merkle::merkle_db::MerkleDB;
use std::{error::Error, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    const EXTRINSICS_POOL_MAX_SIZE: usize = 1000;
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    const STATE_DB_CACHE_SIZE: usize = 1000;
    const HEADER_DB_CACHE_SIZE: usize = 1000;

    let core_db = Arc::new(CoreDB::open(
        PathBuf::from("./.rocksdb"),
        RocksDBOpts::default(),
    )?);

    let merkle_db = MerkleDB::new(core_db.clone(), MERKLE_CF_NAME, MERKLE_DB_CACHE_SIZE);
    let state_db = StateDB::new(core_db.clone(), STATE_CF_NAME, STATE_DB_CACHE_SIZE);
    let mut header_db = BlockHeaderDB::new(core_db, HEADER_CF_NAME, HEADER_DB_CACHE_SIZE);
    let _state_manager = StateManager::new(state_db, merkle_db);
    let _extrinsic_pool = XtPool::new(EXTRINSICS_POOL_MAX_SIZE);

    println!("DB initialized successfully");

    header_db.init_staging_header(Hash32::default())?;
    let _timeslot_index = header_db.set_timeslot()?;
    let header_hash = header_db.commit_staging_header().await?;

    let header_1 = header_db.get_header(&header_hash).await?.unwrap();
    println!("Header 1:");
    println!("{}", header_1);

    Ok(())
}
