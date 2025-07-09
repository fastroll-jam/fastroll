use std::error::Error;

pub struct FuzzRunner;
impl FuzzRunner {
    pub async fn run_as_fuzz_target(socket_addr: Option<String>) -> Result<(), Box<dyn Error>> {
        println!("Running as a fuzz target. Socket: {socket_addr:?}");
        Ok(())
    }
}
