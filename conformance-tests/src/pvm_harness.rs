use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

// --- Types

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ExpectedStatus {
    /// The execution ended with a panic (the `trap` instruction was executed, the execution went
    /// "out of bounds", an invalid jump was made, or an invalid instruction was executed).
    panic,
    /// The execution finished gracefully (a dynamic jump to address `0xffff0000` was made).
    halt,
    /// The execution finished with a page fault.
    page_fault,
}

/// A blob of bytes at a given memory address.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MemoryChunk {
    pub address: u32,
    pub contents: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PageMap {
    pub address: u32,
    pub length: u32,
    pub is_writable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TestCase {
    /// A unique identifier for the test.
    pub name: String,
    /// The initial value of each of the 13 registers; these need to be set before the test program
    /// is executed.
    pub initial_regs: [u64; 13],
    /// The initial program counter from which to start the execution.
    pub initial_pc: u32,
    /// Lists regions of memory which should be accessible, initialized with zeros by default;
    /// any address not on this should be inaccessible.
    pub initial_page_map: Vec<PageMap>,
    /// Lists all non-zero values to put in memory before execution.
    pub initial_memory: MemoryChunk,
    /// The initial amount of gas.
    pub initial_gas: i64,
    /// The program blob to be executed as part of the test.
    pub program: Vec<u8>,
    /// The status code of the execution, i.e. the way the program is supposed to end.
    pub expected_status: ExpectedStatus,
    /// The expected values of each of the 13 registers after the test program is executed.
    pub expected_regs: [u64; 13],
    /// The final value of the program counter, after the execution finishes.
    pub expected_pc: u32,
    /// Lists all non-zero values after the execution finishes; all accessible addresses not on this
    /// must be filled with zeroes.
    pub expected_memory: MemoryChunk,
    /// The final amount of gas remaining after the execution finishes.
    pub expected_gas: i64,
    /// The address of a page fault (only if the program finishes with a page fault).
    pub expected_page_fault_address: Option<u32>,
}

// --- Test Harness

pub const PATH_PREFIX: &str = "jamtestvectors-pvm/pvm/programs";

pub fn load_test_case(filename: &Path) -> TestCase {
    let path = PathBuf::from(PATH_PREFIX).join(filename);
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON")
}
