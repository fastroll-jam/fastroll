use rjam_extrinsics::extrinsics_pool::EXTRINSICS_POOL;

fn main() {
    // Explicitly initialize the extrinsics pool
    lazy_static::initialize(&EXTRINSICS_POOL);
    println!("extrinsic pool initialized successfully");
}
