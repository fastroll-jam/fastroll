use crate::core::{
    cached_db::CachedDB,
    core_db::{CoreDB, CoreDBError},
};
use rjam_common::Hash32;
use std::{ops::Deref, sync::Arc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateDBError {
    #[error("CoreDBError: {0}")]
    CoreDBError(#[from] CoreDBError),
}

pub struct StateDB {
    db: CachedDB<Hash32, Vec<u8>>,
}

impl Deref for StateDB {
    type Target = CachedDB<Hash32, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl StateDB {
    pub fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            db: CachedDB::new(core, cf_name, cache_size),
        }
    }
}
