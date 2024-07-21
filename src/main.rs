use rjam::trie::db::GLOBAL_STATE_MANAGER;

fn main() {
    // Initialize the global state manager
    lazy_static::initialize(&GLOBAL_STATE_MANAGER);

    println!("global state manager initialized");
}
