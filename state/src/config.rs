pub struct StateManagerConfig {
    pub state_cf_name: &'static str,
    pub merkle_cf_name: &'static str,
    pub state_db_cache_size: usize,
    pub merkle_db_cache_size: usize,
}
