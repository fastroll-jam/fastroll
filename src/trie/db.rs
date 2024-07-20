use std::sync::Arc;

// Key-Value database representation

// Placeholder for the key-value database
pub(crate) trait KeyValueDB: Sync + Send {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String>;
}

struct DB {
    inner: Arc<dyn KeyValueDB>,
}

impl DB {
    fn new(inner: Arc<dyn KeyValueDB>) -> Self {
        DB { inner }
    }
}

impl KeyValueDB for DB {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.inner.get(key)
    }
}
