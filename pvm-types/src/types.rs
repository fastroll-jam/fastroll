use crate::{hostcall::HostCallType, memory::MemAddress};

/// PVM Invocation Exit Reasons
pub enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault(MemAddress),
    HostCall(HostCallType),
}
