#[macro_export]
macro_rules! continue_with_reg_write {
    ($vm_state:expr, $program_state:expr, $reg_idx:expr, $reg_val:expr) => {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc($vm_state, $program_state),
                register_write: Some(($reg_idx, $reg_val)),
                ..Default::default()
            },
        })
    };
}

#[macro_export]
macro_rules! continue_with_mem_write {
    ($vm_state:expr, $program_state:expr, $offset:expr, $data:expr) => {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                memory_write: Some(MemWrite::new($offset, $data)),
                new_pc: Interpreter::next_pc($vm_state, $program_state),
                ..Default::default()
            },
        })
    };
}

#[macro_export]
macro_rules! mem_panic {
    () => {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Panic,
            state_change: VMStateChange::default(),
        })
    };
}

#[macro_export]
macro_rules! mem_page_fault {
    ($addr:expr) => {
        Ok(SingleStepResult {
            exit_reason: ExitReason::PageFault($addr),
            state_change: VMStateChange::default(),
        })
    };
}

#[macro_export]
macro_rules! jump_result {
    ($exit_reason:expr, $target:expr) => {
        Ok(SingleStepResult {
            exit_reason: $exit_reason,
            state_change: VMStateChange {
                new_pc: $target,
                ..Default::default()
            },
        })
    };
}

#[macro_export]
macro_rules! jump_result_with_reg_write {
    ($exit_reason:expr, $target:expr, $reg_idx:expr, $reg_val:expr) => {
        Ok(SingleStepResult {
            exit_reason: $exit_reason,
            state_change: VMStateChange {
                new_pc: $target,
                register_write: Some(($reg_idx, $reg_val)),
                ..Default::default()
            },
        })
    };
}
