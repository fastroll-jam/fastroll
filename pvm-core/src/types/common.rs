use crate::{
    constants::DATA_SEGMENTS_SIZE, state::memory::MemAddress, types::hostcall::HostCallType,
};

/// PVM Invocation Exit Reasons
pub enum ExitReason {
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,
    PageFault(MemAddress),
    HostCall(HostCallType),
}

pub type RegValue = u64;
pub type ExportDataSegment = [u8; DATA_SEGMENTS_SIZE];
