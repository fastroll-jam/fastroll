use jam_db::manager::GLOBAL_KVDB_MANAGER;
use jam_extrinsics::extrinsics_pool::EXTRINSICS_POOL;
use jam_state::cache::STATE_CACHE;

// TODO: Evaluate between static global singleton initialization (current model)
// TODO: vs. Dependency Injection of manager instances (KVDB, ExtrinsicsPool)
fn main() {
    // Explicitly initialize the extrinsics pool
    lazy_static::initialize(&EXTRINSICS_POOL);
    println!("extrinsic pool initialized successfully");

    // Explicitly initialize the state cache
    lazy_static::initialize(&STATE_CACHE);
    println!("state cache initialized successfully");

    // Explicitly initialize the global state manager
    lazy_static::initialize(&GLOBAL_KVDB_MANAGER);
    println!("global state manager initialized successfully");
}
