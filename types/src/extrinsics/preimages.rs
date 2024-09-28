use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{AccountAddress, Octets};

#[derive(Debug, Clone, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PreimageLookupExtrinsicEntry {
    service_index: AccountAddress, // N_S
    preimage_data: Octets,
}
