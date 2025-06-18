#[macro_export]
macro_rules! continue_with_reg_write {
    ($vm_state:expr, $program_state:expr, $reg_idx:expr, $reg_val:expr) => {
        Ok(SingleStepResult {
            exit_reason: ExitReason::Continue,
            state_change: VMStateChange {
                new_pc: Interpreter::next_pc($vm_state, $program_state),
                register_write: Some(($reg_idx, $reg_val)),
                ..Default::default()
            }
        })
    };
}