use fr_common::SEGMENT_SIZE;
use fr_limited_vec::FixedVec;

/// 32-bit memory addresses
pub type MemAddress = u32;

/// 64-bit register values
pub type RegValue = u64;

/// An exported data segment unit, stored under erasure-coded DAs.
pub type ExportDataSegment = FixedVec<u8, SEGMENT_SIZE>;
