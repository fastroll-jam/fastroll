use rjam_common::UnsignedGas;
use rjam_pvm_core::{
    constants::{MEMORY_SIZE, PAGE_SIZE},
    core::VMState,
    state::{
        memory::{AccessType, Memory},
        register::Register,
    },
    types::common::RegValue,
};
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
struct MemoryChunk {
    pub address: u32,
    pub contents: Vec<u8>,
}

impl MemoryChunk {
    fn write_to_memory(&self, memory: &mut Memory) {
        memory
            .write_bytes(self.address, &self.contents)
            .expect("Failed to write memory");
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PageMap {
    pub address: u32,
    pub length: u32,
    pub is_writable: bool,
}

impl PageMap {
    fn set_access(&self, memory: &mut Memory) {
        let access_type = if self.is_writable {
            AccessType::ReadWrite
        } else {
            AccessType::ReadOnly
        };

        memory
            .set_address_range_access(self.address..(self.address + self.length), access_type)
            .expect("Failed to set access");
    }
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
    pub initial_memory: Vec<MemoryChunk>,
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
    pub expected_memory: Vec<MemoryChunk>,
    /// The final amount of gas remaining after the execution finishes.
    pub expected_gas: i64,
    /// The address of a page fault (only if the program finishes with a page fault).
    pub expected_page_fault_address: Option<u32>,
}

pub struct ParsedTestCase {
    initial_vm: VMState,
    program: Vec<u8>,
    expected_vm: VMState,
    expected_status: ExpectedStatus,
    expected_page_fault_address: Option<u32>,
}

// --- Test Harness

const PATH_PREFIX: &str = "jamtestvectors-pvm/pvm/programs";

pub fn load_test_case(filename: &Path) -> TestCase {
    let path = PathBuf::from(PATH_PREFIX).join(filename);
    let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
    serde_json::from_str(&json_str).expect("Failed to parse JSON")
}

pub fn parse_test_case(test_case: TestCase) -> ParsedTestCase {
    // --- Initial VM State
    let mut initial_vm = VMState {
        registers: [Register::default(); 13],
        memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
        pc: test_case.initial_pc as RegValue,
        gas_counter: test_case.initial_gas as UnsignedGas,
    };

    // Setup registers
    for (i, val) in test_case.initial_regs.iter().enumerate() {
        initial_vm.registers[i] = Register::new(*val);
    }

    // Setup memory
    for page_map in &test_case.initial_page_map {
        page_map.set_access(&mut initial_vm.memory);
    }

    // Load initial data to value
    for memory_chunk in test_case.initial_memory {
        memory_chunk.write_to_memory(&mut initial_vm.memory);
    }

    // --- Expected VM State after program run
    let mut expected_vm = VMState {
        registers: [Register::default(); 13],
        memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
        pc: test_case.expected_pc as RegValue,
        gas_counter: test_case.expected_gas as UnsignedGas,
    };

    // Setup registers
    for (i, val) in test_case.expected_regs.iter().enumerate() {
        expected_vm.registers[i] = Register::new(*val);
    }

    // Setup memory
    for page_map in &test_case.initial_page_map {
        page_map.set_access(&mut expected_vm.memory);
    }

    // Load initial data to value
    for memory_chunk in test_case.expected_memory {
        memory_chunk.write_to_memory(&mut expected_vm.memory);
    }

    ParsedTestCase {
        initial_vm,
        program: test_case.program,
        expected_vm,
        expected_status: test_case.expected_status,
        expected_page_fault_address: test_case.expected_page_fault_address,
    }
}
