use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::Address;

#[derive(Debug, Clone, Copy, JamEncode, JamDecode)]
pub struct PrivilegedServices {
    pub empower_service_index: Address,   // m; N_S
    pub assign_service_index: Address,    // a; N_S
    pub designate_service_index: Address, // v; N_S
}
