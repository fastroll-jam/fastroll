use crate::{
    error::{PVMError, VMCoreError::*},
    utils::VMUtils,
};
use rjam_codec::{JamCodecError, JamDecode, JamDecodeFixed, JamInput};
use rjam_pvm_types::constants::{
    INIT_INPUT_SIZE, INIT_ZONE_SIZE, PAGE_SIZE, STANDARD_PROGRAM_SIZE_LIMIT,
};

pub struct FormattedProgram {
    /// `|o|`: Read-only data size
    pub static_size: u32,
    /// `|w|`: Read-write data size
    pub heap_size: u32,
    /// `z`: Extra heap allocation in pages
    pub extra_heap_pages: u16,
    /// `s`: Stack area size
    pub stack_size: u32,
    /// `o`: Read-only data of the program
    pub static_data: Vec<u8>,
    /// `w`: Read-write data of the program
    pub heap_data: Vec<u8>,
    /// `|c|`: Program code size
    pub code_size: u32,
    /// `c`: Program code blob; encoding of instructions, an opcode bitmask and a dynamic jump table.
    pub code: Vec<u8>,
}

impl JamDecode for FormattedProgram {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        let static_size = u32::decode_fixed(input, 3)?;
        let heap_size = u32::decode_fixed(input, 3)?;
        let extra_heap_pages = u16::decode_fixed(input, 2)?;
        let stack_size = u32::decode_fixed(input, 3)?;
        let static_data = Vec::<u8>::decode_fixed(input, static_size as usize)?; // no length prefix
        let heap_data = Vec::<u8>::decode_fixed(input, heap_size as usize)?; // no length prefix
        let code_size = u32::decode_fixed(input, 4)?;
        let code = Vec::<u8>::decode_fixed(input, code_size as usize)?; // no length prefix

        Ok(Self {
            static_size,
            heap_size,
            extra_heap_pages,
            stack_size,
            static_data,
            heap_data,
            code_size,
            code,
        })
    }
}

impl FormattedProgram {
    /// Decodes program blob into formatted program. Used by `Ψ_M`.
    pub fn from_standard_program(program_blob: &[u8]) -> Result<Self, PVMError> {
        let mut input = program_blob;
        let formatted_program = Self::decode(&mut input)?;
        if !input.is_empty() {
            return Err(PVMError::VMCoreError(InvalidProgram));
        }
        Ok(formatted_program)
    }

    pub fn is_program_size_valid(&self) -> bool {
        5 * INIT_ZONE_SIZE
            + VMUtils::zone_align(self.static_size as usize)
            + VMUtils::zone_align(
                self.heap_size as usize + (self.extra_heap_pages as usize) * PAGE_SIZE,
            )
            + VMUtils::zone_align(self.stack_size as usize)
            + INIT_INPUT_SIZE
            <= STANDARD_PROGRAM_SIZE_LIMIT
    }
}
