use fr_common::{
    utils::{serde::FileReader, tracing::setup_timed_tracing},
    UnsignedGas,
};
use fr_pvm_core::{
    interpreter::{GeneralInvocationResult, Interpreter},
    program::{loader::ProgramLoader, types::program_state::ProgramState},
    state::{
        memory::{AccessType, Memory},
        vm_state::{RegIndex, Registers, VMState},
    },
};
use fr_pvm_types::{
    common::RegValue,
    constants::{MEMORY_SIZE, PAGE_SIZE},
    exit_reason::ExitReason,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

// --- Types

/// Exit status that an `assert` step of a PVM test vector expects from the last `run` step.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedStatus {
    /// The execution ended with a panic (the `trap` instruction was executed, the execution went
    /// "out of bounds", an invalid jump was made, or an invalid instruction was executed).
    Panic,
    /// The execution finished gracefully (a dynamic jump to address `0xffff0000` was made).
    Halt,
    /// The execution was interrupted with a page fault.
    PageFault,
    /// The execution ran out of gas.
    OutOfGas,
    /// The execution was interrupted by an `ecalli` instruction.
    Ecalli,
}

impl ExpectedStatus {
    fn from_exit_reason(exit_reason: &ExitReason) -> Self {
        match exit_reason {
            ExitReason::Panic => Self::Panic,
            ExitReason::RegularHalt => Self::Halt,
            ExitReason::PageFault(_) => Self::PageFault,
            ExitReason::OutOfGas => Self::OutOfGas,
            ExitReason::HostCall(_) => Self::Ecalli,
            ExitReason::Continue => panic!("Ψ returned without an exit"),
        }
    }
}

/// A blob of bytes at a given memory address.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct MemoryChunk {
    address: u32,
    contents: Vec<u8>,
}

/// A page-aligned memory region that a `map` step makes accessible.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PageMap {
    address: u32,
    length: u32,
    #[serde(rename = "is-writable")]
    is_writable: bool,
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

/// A register value that a `set-reg` step writes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct RegisterValue {
    /// 0-based register index
    #[serde(rename = "reg")]
    register_index: RegIndex,
    value: RegValue,
}

/// VM state that an `assert` step expects after the last `run` step. Absent fields are not checked.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
struct ExpectedState {
    status: ExpectedStatus,
    regs: Option<Registers>,
    /// PC of the instruction that caused the exit, also on halt or panic
    pc: Option<u32>,
    /// All non-zero bytes of the mapped memory
    memory: Option<Vec<MemoryChunk>>,
    gas: Option<i64>,
    page_fault_address: Option<u32>,
    #[serde(rename = "hostcall")]
    host_call_id: Option<u32>,
}

/// A step of a PVM test vector, run in order on one VM.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TestStep {
    /// Starts `Ψ`, or resumes it after the last exit. A host call resumes at the next instruction, as `Ψ_H` does.
    Run {},
    #[serde(rename = "set-reg")]
    SetRegister(RegisterValue),
    Map(PageMap),
    /// Writes into memory regardless of the page access
    Write(MemoryChunk),
    Assert(ExpectedState),
}

/// Gas cost of the basic block that starts at `pc` (0-based, in octets).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
struct BasicBlockGasCost {
    pc: usize,
    cost: UnsignedGas,
}

/// PVM test vector of the `programs` directory, which runs a program blob step by step.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TestCase {
    name: String,
    initial_pc: u32,
    initial_gas: i64,
    program: Vec<u8>,
    block_gas_costs: Vec<BasicBlockGasCost>,
    steps: Vec<TestStep>,
}

/// PVM test vector of the `gas-tests` directory, which checks only the gas cost of every basic block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct BasicBlockGasCostTestCase {
    name: String,
    program: Vec<u8>,
    /// Gas cost by basic block start, unlike the list of `TestCase`
    block_gas_costs: BTreeMap<usize, UnsignedGas>,
}

/// Compares the basic block starts and their gas costs of a loaded program with the expected ones.
fn assert_block_gas_costs(
    program_state: &ProgramState,
    expected_block_gas_costs: &[BasicBlockGasCost],
    test_name: &str,
) {
    let mut expected_block_gas_costs = expected_block_gas_costs.to_vec();
    expected_block_gas_costs.sort_by_key(|block_gas_cost| block_gas_cost.pc);
    let actual_block_gas_costs: Vec<BasicBlockGasCost> = program_state
        .basic_block_start_indices
        .iter_ones()
        .zip(&program_state.basic_block_gas_costs)
        .map(|(pc, &cost)| BasicBlockGasCost { pc, cost })
        .collect();
    for (actual, expected) in actual_block_gas_costs.iter().zip(&expected_block_gas_costs) {
        assert_eq!(actual, expected, "{test_name}: block gas cost");
    }
    assert_eq!(
        actual_block_gas_costs.len(),
        expected_block_gas_costs.len(),
        "{test_name}: basic block count"
    );
}

/// VM under test with the memory regions mapped so far, which `write` and `assert` steps need.
struct TestVM {
    vm_state: VMState,
    program_state: ProgramState,
    page_maps: Vec<PageMap>,
    last_invocation_result: Option<GeneralInvocationResult>,
}

impl TestVM {
    fn new(test_case: &TestCase) -> Self {
        let mut program_state = ProgramState::default();
        ProgramLoader::load_program(&test_case.program, &mut program_state)
            .expect("Failed to load program");
        Self {
            vm_state: VMState {
                regs: Registers::default(),
                memory: Memory::new(MEMORY_SIZE, PAGE_SIZE),
                pc: test_case.initial_pc as RegValue,
                gas_counter: test_case.initial_gas,
                is_basic_block_gas_charged: false,
            },
            program_state,
            page_maps: Vec::new(),
            last_invocation_result: None,
        }
    }

    fn run_step(&mut self, step: &TestStep, test_name: &str) {
        match step {
            TestStep::Run {} => self.run(),
            TestStep::SetRegister(register_value) => {
                self.vm_state.regs[register_value.register_index] = register_value.value;
            }
            TestStep::Map(page_map) => {
                page_map.set_access(&mut self.vm_state.memory);
                self.page_maps.push(page_map.clone());
            }
            TestStep::Write(memory_chunk) => self.write_memory(memory_chunk),
            TestStep::Assert(expected_state) => self.assert_state(expected_state, test_name),
        }
    }

    fn run(&mut self) {
        if let Some(GeneralInvocationResult {
            exit_reason: ExitReason::HostCall(_),
            ..
        }) = self.last_invocation_result
        {
            self.vm_state.pc = Interpreter::next_pc(self.vm_state.pc, &self.program_state);
        }
        let invocation_result =
            Interpreter::invoke_general(&mut self.vm_state, &self.program_state)
                .expect("Failed to run PVM");
        self.last_invocation_result = Some(invocation_result);
    }

    /// Writes with read-write access, then restores the access of every mapped region.
    fn write_memory(&mut self, memory_chunk: &MemoryChunk) {
        let memory = &mut self.vm_state.memory;
        let write_end = memory_chunk.address + memory_chunk.contents.len() as u32;
        memory
            .set_address_range_access(memory_chunk.address..write_end, AccessType::ReadWrite)
            .expect("Failed to set access");
        memory
            .write_bytes(memory_chunk.address, &memory_chunk.contents)
            .expect("Failed to write memory");
        for page_map in &self.page_maps {
            page_map.set_access(memory);
        }
    }

    fn assert_state(&self, expected_state: &ExpectedState, test_name: &str) {
        let invocation_result = self
            .last_invocation_result
            .as_ref()
            .expect("An assert step must follow a run step");
        let exit_reason = &invocation_result.exit_reason;
        assert_eq!(
            ExpectedStatus::from_exit_reason(exit_reason),
            expected_state.status,
            "{test_name}: status"
        );
        if let Some(expected_regs) = &expected_state.regs {
            assert_eq!(&self.vm_state.regs, expected_regs, "{test_name}: regs");
        }
        if let Some(expected_pc) = expected_state.pc {
            assert_eq!(
                invocation_result.exiting_instruction_pc, expected_pc as RegValue,
                "{test_name}: pc"
            );
        }
        if let Some(expected_gas) = expected_state.gas {
            assert_eq!(self.vm_state.gas_counter, expected_gas, "{test_name}: gas");
        }
        if let Some(expected_memory) = &expected_state.memory {
            self.assert_mapped_memory(expected_memory, test_name);
        }
        let page_fault_address = match exit_reason {
            ExitReason::PageFault(address) => Some(*address),
            _ => None,
        };
        assert_eq!(
            page_fault_address, expected_state.page_fault_address,
            "{test_name}: page fault address"
        );
        let host_call_id = match exit_reason {
            ExitReason::HostCall(host_call_id) => Some(*host_call_id as u32),
            _ => None,
        };
        assert_eq!(
            host_call_id, expected_state.host_call_id,
            "{test_name}: host call id"
        );
    }

    /// Compares every mapped byte with the expected chunks, where unlisted bytes are expected to be zero.
    fn assert_mapped_memory(&self, expected_memory: &[MemoryChunk], test_name: &str) {
        for page_map in &self.page_maps {
            let mut expected_bytes = vec![0u8; page_map.length as usize];
            for chunk in expected_memory {
                for (offset, byte) in chunk.contents.iter().enumerate() {
                    let address = chunk.address as usize + offset;
                    if let Some(index) = address.checked_sub(page_map.address as usize) {
                        if let Some(expected_byte) = expected_bytes.get_mut(index) {
                            *expected_byte = *byte;
                        }
                    }
                }
            }
            let actual_bytes = self
                .vm_state
                .memory
                .read_bytes(page_map.address, page_map.length as usize)
                .expect("Failed to read mapped memory");
            assert_eq!(
                actual_bytes, expected_bytes,
                "{test_name}: memory at {:#x}",
                page_map.address
            );
        }
    }
}

// --- Test Harness

pub struct PVMHarness;
impl PVMHarness {
    const PATH_PREFIX: &'static str = "jamtestvectors-pvm/pvm";

    /// Reads a test vector from `directory` (e.g. `programs`) of the PVM test vectors.
    fn load_test_case<T: Serialize + DeserializeOwned>(directory: &str, filename: &str) -> T {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../integration")
            .join(Self::PATH_PREFIX)
            .join(directory)
            .join(filename);
        FileReader::read_json(&full_path).expect("Failed to read PVM test case")
    }
}

pub fn run_test_case(filename: &str) {
    setup_timed_tracing();
    let test_case: TestCase = PVMHarness::load_test_case("programs", filename);
    let mut test_vm = TestVM::new(&test_case);
    assert_block_gas_costs(
        &test_vm.program_state,
        &test_case.block_gas_costs,
        &test_case.name,
    );
    for step in &test_case.steps {
        test_vm.run_step(step, &test_case.name);
    }
}

pub fn run_block_gas_cost_test_case(filename: &str) {
    setup_timed_tracing();
    let test_case: BasicBlockGasCostTestCase = PVMHarness::load_test_case("gas-tests", filename);
    let mut program_state = ProgramState::default();
    ProgramLoader::load_program(&test_case.program, &mut program_state)
        .expect("Failed to load program");
    let expected_block_gas_costs: Vec<BasicBlockGasCost> = test_case
        .block_gas_costs
        .into_iter()
        .map(|(pc, cost)| BasicBlockGasCost { pc, cost })
        .collect();
    assert_block_gas_costs(&program_state, &expected_block_gas_costs, &test_case.name);
}
