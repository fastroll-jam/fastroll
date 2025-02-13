use crate::{constants::SEGMENT_SIZE, state::memory::MemAddress, types::hostcall::HostCallType};

/// PVM Invocation Exit Reasons
#[derive(Default)]
pub enum ExitReason {
    #[default]
    Continue,
    RegularHalt,
    Panic,
    OutOfGas,              // Note: Not used in the single-step invocation.
    PageFault(MemAddress), // FIXME: return the lowest address of the page (GP v0.6.0)
    HostCall(HostCallType),
}

pub type RegValue = u64;
pub type ExportDataSegment = Box<[u8; SEGMENT_SIZE]>;
