use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::AccountAddress;

#[derive(Debug, Clone, Copy, JamEncode, JamDecode)]
pub struct PrivilegedServices {
    pub empower_service_index: AccountAddress,   // m; N_S
    pub assign_service_index: AccountAddress,    // a; N_S
    pub designate_service_index: AccountAddress, // v; N_S
}
