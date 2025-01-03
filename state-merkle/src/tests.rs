//! MerkleDB Integration Tests
#[cfg(test)]
mod tests {
    use crate::{codec::tests::*, merkle_db::MerkleDB};
    use rjam_db::RocksDBConfig;
    use tempfile::tempdir;

    fn init_db() -> MerkleDB {
        const MERKLE_DB_CACHE_SIZE: usize = 1000;
        MerkleDB::open(
            &RocksDBConfig::from_path(tempdir().unwrap().into_path().join("merkle_db")),
            MERKLE_DB_CACHE_SIZE,
        )
        .unwrap()
    }

    #[test]
    fn merkle_db_test() {
        let db = init_db();
        let branch = generate_branch(simple_hash("0"), simple_hash("1"));
        let regular_leaf = generate_regular_leaf(simple_hash("0"), &some_large_blob());
        let embedded_leaf = generate_embedded_leaf(simple_hash("0"), &some_small_blob());

        db.put_node(&branch).unwrap();
        db.put_node(&regular_leaf).unwrap();
        db.put_node(&embedded_leaf).unwrap();
        println!("PUT operation done.");

        print_node(&db.get_node(&branch.hash).unwrap()); // FIXME: `parse_node_data` for branch node
        print_node(&db.get_node(&regular_leaf.hash).unwrap());
        print_node(&db.get_node(&embedded_leaf.hash).unwrap());
    }
}
