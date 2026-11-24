use crate::common::{MemAddress, RegValue};

/// PVM Invocation Exit Reasons
#[derive(Default, Debug, PartialEq)]
pub enum ExitReason {
    #[default]
    Continue,
    RegularHalt,
    Panic,
    OutOfGas, // Note: Not used in the single-step invocation.
    PageFault(MemAddress),
    /// Host call with its id `h`, the full immediate of `ecalli`.
    HostCall(RegValue),
}
