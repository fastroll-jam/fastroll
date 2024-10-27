use rjam_extrinsics::pool::EXTRINSICS_POOL;

fn main() {
    // Explicitly initialize the extrinsics pool
    lazy_static::initialize(&EXTRINSICS_POOL);
    println!("extrinsic pool initialized successfully");
}
