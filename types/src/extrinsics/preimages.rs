use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, Octets};

#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PreimageLookupExtrinsicEntry {
    service_index: Address, // N_S
    preimage_data: Octets,
}
