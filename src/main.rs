use rjam::db::manager::GLOBAL_KVDB_MANAGER;

fn main() {
    // Initialize the global state manager
    lazy_static::initialize(&GLOBAL_KVDB_MANAGER);

    println!("global state manager initialized");
}
