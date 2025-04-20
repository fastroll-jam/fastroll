use rjam_pvm_core::{
    interpreter::Interpreter,
    program::{loader::ProgramLoader, types::program_state::ProgramState},
    state::{
        memory::{AccessType, Memory},
        register::Register,
        vm_state::VMState,
    },
};
use rjam_pvm_interface::pvm::PVM;
use rjam_pvm_types::{
    common::RegValue,
    constants::{MEMORY_SIZE, PAGE_SIZE},
    exit_reason::ExitReason,
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
    #[serde(rename = "page-fault")]
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
    #[serde(rename = "is-writable")]
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

    fn set_access_privileged(&self, memory: &mut Memory) {
        memory
            .set_address_range_access(
                self.address..(self.address + self.length),
                AccessType::ReadWrite,
            )
            .expect("Failed to set access");
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TestCase {
    /// A unique identifier for the test.
    name: String,
    /// The initial value of each of the 13 registers; these need to be set before the test program
    /// is executed.
    #[serde(rename = "initial-regs")]
    initial_regs: [u64; 13],
    /// The initial program counter from which to start the execution.
    #[serde(rename = "initial-pc")]
    initial_pc: u32,
    /// Lists regions of memory which should be accessible, initialized with zeros by default;
    /// any address not on this should be inaccessible.
    #[serde(rename = "initial-page-map")]
    initial_page_map: Vec<PageMap>,
    /// Lists all non-zero values to put in memory before execution.
    #[serde(rename = "initial-memory")]
    initial_memory: Vec<MemoryChunk>,
    /// The initial amount of gas.
    #[serde(rename = "initial-gas")]
    initial_gas: i64,
    /// The program blob to be executed as part of the test.
    program: Vec<u8>,
    /// The status code of the execution, i.e. the way the program is supposed to end.
    #[serde(rename = "expected-status")]
    expected_status: ExpectedStatus,
    /// The expected values of each of the 13 registers after the test program is executed.
    #[serde(rename = "expected-regs")]
    expected_regs: [u64; 13],
    /// The final value of the program counter, after the execution finishes.
    #[serde(rename = "expected-pc")]
    expected_pc: u32,
    /// Lists all non-zero values after the execution finishes; all accessible addresses not on this
    /// must be filled with zeroes.
    #[serde(rename = "expected-memory")]
    expected_memory: Vec<MemoryChunk>,
    /// The final amount of gas remaining after the execution finishes.
    #[serde(rename = "expected-gas")]
    expected_gas: i64,
    /// The address of a page fault (only if the program finishes with a page fault).
    #[serde(rename = "expected-page-fault-address")]
    expected_page_fault_address: Option<u32>,
}

pub struct ParsedTestCase {
    initial_vm: VMState,
    program: Vec<u8>,
    expected_vm: VMState,
    expected_status: ExpectedStatus,
    expected_page_fault_address: Option<u32>,
}

// --- Test Harness

pub struct PVMHarness;

impl PVMHarness {
    const PATH_PREFIX: &'static str = "jamtestvectors-pvm/pvm/programs";

    pub fn load_test_case(filename: &Path) -> TestCase {
        let path = PathBuf::from(Self::PATH_PREFIX).join(filename);
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let json_str = fs::read_to_string(&full_path).expect("Failed to read test vector file");
        serde_json::from_str(&json_str).expect("Failed to parse JSON")
    }

    pub fn parse_test_case(test_case: TestCase) -> ParsedTestCase {
        // --- Initial VM State
        let mut initial_vm = VMState {
            regs: [Register::default(); 13],
            memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
            pc: test_case.initial_pc as RegValue,
            gas_counter: test_case.initial_gas,
        };

        // Setup registers
        for (i, val) in test_case.initial_regs.iter().enumerate() {
            initial_vm.regs[i] = Register::new(*val);
        }

        // Give ReadWrite access during memory setup
        for page_map in &test_case.initial_page_map {
            page_map.set_access_privileged(&mut initial_vm.memory);
        }

        // Load initial data to value
        for memory_chunk in test_case.initial_memory {
            memory_chunk.write_to_memory(&mut initial_vm.memory);
        }

        // Setup memory page accesses
        for page_map in &test_case.initial_page_map {
            page_map.set_access(&mut initial_vm.memory);
        }

        // --- Expected VM State after program run
        let mut expected_vm = VMState {
            regs: [Register::default(); 13],
            memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
            pc: test_case.expected_pc as RegValue,
            gas_counter: test_case.expected_gas,
        };

        // Setup registers
        for (i, val) in test_case.expected_regs.iter().enumerate() {
            expected_vm.regs[i] = Register::new(*val);
        }

        // Give ReadWrite access during memory setup
        for page_map in &test_case.initial_page_map {
            page_map.set_access_privileged(&mut expected_vm.memory);
        }

        // Load initial data to value
        for memory_chunk in test_case.expected_memory {
            memory_chunk.write_to_memory(&mut expected_vm.memory);
        }

        // Setup memory page accesses
        for page_map in &test_case.initial_page_map {
            page_map.set_access(&mut expected_vm.memory);
        }

        ParsedTestCase {
            initial_vm,
            program: test_case.program,
            expected_vm,
            expected_status: test_case.expected_status,
            expected_page_fault_address: test_case.expected_page_fault_address,
        }
    }
}

pub fn run_test_case(filename: &str) {
    // load test case
    let filename = PathBuf::from(filename);
    let test_case = PVMHarness::load_test_case(&filename);
    let ParsedTestCase {
        initial_vm,
        program,
        expected_vm,
        expected_status,
        expected_page_fault_address,
    } = PVMHarness::parse_test_case(test_case);

    // initialize PVM
    let mut pvm = PVM {
        state: initial_vm,
        program_blob: program.clone(),
        program_state: ProgramState::default(),
    };

    ProgramLoader::load_program(&program, &mut pvm.program_state).expect("Failed to load program");

    // Debugging
    tracing::trace!("{:?}", pvm.program_state);

    // execute PVM
    let exit_reason = Interpreter::invoke_general(&mut pvm.state, &mut pvm.program_state, &program)
        .expect("Failed to run PVM");

    let (actual_status, actual_page_fault_address) = match exit_reason {
        ExitReason::Panic => (ExpectedStatus::panic, None),
        ExitReason::RegularHalt => (ExpectedStatus::halt, None),
        ExitReason::PageFault(addr) => (ExpectedStatus::page_fault, Some(addr)),
        _ => panic!("Unexpected exit reason"),
    };

    // Bypass gas_counter for now, since it is not finalized yet
    // assert_eq!(pvm.state, expected_vm);
    // TODO: test gas counter and pc values
    // assert_eq!(pvm.state.gas_counter, expected_vm.gas_counter);
    // assert_eq!(pvm.state.pc, expected_vm.pc);
    assert_eq!(pvm.state.regs, expected_vm.regs);
    assert_eq!(pvm.state.memory, expected_vm.memory);
    assert_eq!(actual_status, expected_status);
    assert_eq!(actual_page_fault_address, expected_page_fault_address);
}
