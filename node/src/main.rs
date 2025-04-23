pub(crate) mod config;
pub(crate) mod timeslot_scheduler;

use rjam_block::header_db::BlockHeaderDB;
use rjam_common::{utils::tracing::setup_tracing, Hash32};
use rjam_db::{
    config::{RocksDBOpts, HEADER_CF_NAME, MERKLE_CF_NAME, STATE_CF_NAME},
    core::core_db::CoreDB,
};
use rjam_extrinsics::pool::XtPool;
use rjam_state::{config::StateManagerConfig, manager::StateManager};
use std::{error::Error, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Config tracing subscriber
    setup_tracing();

    const EXTRINSICS_POOL_MAX_SIZE: usize = 1000;
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    const STATE_DB_CACHE_SIZE: usize = 1000;
    const HEADER_DB_CACHE_SIZE: usize = 1000;

    let state_manager_config = StateManagerConfig {
        state_cf_name: STATE_CF_NAME,
        state_db_cache_size: STATE_DB_CACHE_SIZE,
        merkle_cf_name: MERKLE_CF_NAME,
        merkle_db_cache_size: MERKLE_DB_CACHE_SIZE,
    };

    let core_db = Arc::new(CoreDB::open(
        PathBuf::from("./.rocksdb"),
        RocksDBOpts::default(),
    )?);

    let mut header_db = BlockHeaderDB::new(core_db.clone(), HEADER_CF_NAME, HEADER_DB_CACHE_SIZE);
    let _state_manager = StateManager::from_core_db(core_db, state_manager_config);
    let _extrinsic_pool = XtPool::new(EXTRINSICS_POOL_MAX_SIZE);

    tracing::info!("DB initialized successfully");

    header_db.init_staging_header(Hash32::default())?;
    let _timeslot_index = header_db.set_timeslot()?;
    let header_hash = header_db.commit_staging_header().await?;

    let header_1 = header_db.get_header(&header_hash).await?.unwrap();
    tracing::debug!("Header 1: {header_1}");

    Ok(())
}
