use crate::{constants::DATA_SEGMENTS_SIZE, hostcall::HostCallType, memory::MemAddress};

/// PVM Invocation Exit Reasons
pub enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault(MemAddress),
    HostCall(HostCallType),
}

pub type ExportDataSegment = [u8; DATA_SEGMENTS_SIZE];
