use crate::codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};

pub(crate) struct PrivilegedServices {
    empower_service_index: u32,   // m; N_S
    assign_service_index: u32,    // a; N_S
    designate_service_index: u32, // v; N_S
}

impl JamEncode for PrivilegedServices {
    fn size_hint(&self) -> usize {
        self.empower_service_index.size_hint()
            + self.assign_service_index.size_hint()
            + self.designate_service_index.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.empower_service_index.encode_to(dest)?;
        self.assign_service_index.encode_to(dest)?;
        self.designate_service_index.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for PrivilegedServices {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            empower_service_index: u32::decode(input)?,
            assign_service_index: u32::decode(input)?,
            designate_service_index: u32::decode(input)?,
        })
    }
}
