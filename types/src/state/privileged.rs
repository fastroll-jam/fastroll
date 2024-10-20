use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, UnsignedGas};
use std::collections::HashMap;

#[derive(Debug, Clone, JamEncode, JamDecode)]
pub struct PrivilegedServices {
    pub manager_service: Address, // m; Alters state privileged services (`chi`).
    pub assign_service: Address,  // a; Alters auth queue (`phi`).
    pub designate_service: Address, // v; Alters staging validator set (`iota`).
    pub always_accumulate_services: HashMap<Address, UnsignedGas>, // g; Basic gas usage of always-accumulate services.
}
