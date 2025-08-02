use crate::{common::MemAddress, hostcall::HostCallType};

/// PVM Invocation Exit Reasons
#[derive(Default, Debug, PartialEq)]
pub enum ExitReason {
    #[default]
    Continue,
    RegularHalt,
    Panic,
    OutOfGas, // Note: Not used in the single-step invocation.
    PageFault(MemAddress),
    HostCall(HostCallType),
}
