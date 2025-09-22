use crate::types::{FullMerklePath, MerkleNode, MerklePath};
use fr_common::MerkleRoot;
use fr_db::core::{cached_db::CachedDB, core_db::CoreDB};
use std::sync::Arc;

struct MerkleDB {
    nodes: CachedDB<MerklePath, MerkleNode>,
    leaf_nodes: CachedDB<FullMerklePath, MerkleNode>,
    root: MerkleRoot,
}

impl MerkleDB {
    fn new(core: Arc<CoreDB>, cf_name: &'static str, cache_size: usize) -> Self {
        Self {
            nodes: CachedDB::new(core.clone(), cf_name, cache_size),
            leaf_nodes: CachedDB::new(core.clone(), "leaf_nodes", cache_size), // FIXME cf name
            root: MerkleRoot::default(),
        }
    }
}
