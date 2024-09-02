use jam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use jam_common::AccountAddress;

#[derive(Clone, Copy)]
pub struct PrivilegedServices {
    pub empower_service_index: AccountAddress,   // m; N_S
    pub assign_service_index: AccountAddress,    // a; N_S
    pub designate_service_index: AccountAddress, // v; N_S
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
            empower_service_index: AccountAddress::decode(input)?,
            assign_service_index: AccountAddress::decode(input)?,
            designate_service_index: AccountAddress::decode(input)?,
        })
    }
}
