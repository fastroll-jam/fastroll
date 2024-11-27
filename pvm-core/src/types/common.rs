use crate::{
    constants::DATA_SEGMENTS_SIZE, state::memory::MemAddress, types::hostcall::HostCallType,
};

/// PVM Invocation Exit Reasons
#[derive(Default)]
pub enum ExitReason {
    #[default]
    Continue,
    RegularHalt,
    Panic,
    OutOfGas, // Note: Not used in the single-step invocation.
    PageFault(MemAddress),
    HostCall(HostCallType),
}

pub type RegValue = u64;
pub type ExportDataSegment = [u8; DATA_SEGMENTS_SIZE];
