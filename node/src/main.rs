pub(crate) mod config;
pub(crate) mod timeslot_scheduler;

use rjam_common::HASH32_EMPTY;
use rjam_db::{core::CoreDB, header_db::BlockHeaderDB};
use rjam_extrinsics::pool::ExtrinsicsPool;
use rjam_state::StateManager;
use rjam_state_merkle::{merkle_db::MerkleDB, state_db::StateDB};
use std::{error::Error, path::PathBuf, sync::Arc};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    const EXTRINSICS_POOL_MAX_SIZE: usize = 1000;
    const MERKLE_DB_CACHE_SIZE: usize = 1000;
    const HEADER_DB_CACHE_SIZE: usize = 1000;

    let core_db = Arc::new(CoreDB::open(PathBuf::from("./.rocksdb"), true)?);

    let merkle_db = MerkleDB::new(core_db.clone(), MERKLE_DB_CACHE_SIZE);
    let state_db = StateDB::new(core_db.clone());
    let mut header_db = BlockHeaderDB::new(core_db, HEADER_DB_CACHE_SIZE);
    let _state_manager = StateManager::new(state_db, merkle_db);
    let _extrinsic_pool = ExtrinsicsPool::new(EXTRINSICS_POOL_MAX_SIZE);

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
