use fr_db::config::{MERKLE_CF_NAME, STATE_CF_NAME};

pub struct StateManagerConfig {
    pub state_cf_name: &'static str,
    pub merkle_cf_name: &'static str,
    pub state_db_cache_size: usize,
    pub merkle_db_cache_size: usize,
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            state_cf_name: STATE_CF_NAME,
            merkle_cf_name: MERKLE_CF_NAME,
            state_db_cache_size: 1024,
            merkle_db_cache_size: 1024,
        }
    }
}
