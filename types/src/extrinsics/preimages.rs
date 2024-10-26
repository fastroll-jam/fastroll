use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, Octets};

/// # Ordering and Validation Rules for Extrinsic Components
/// - `items` must be ordered by `service_index` of each entry.
/// - `items` must have no duplicate entries.
#[derive(Debug, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsic {
    items: Vec<PreimageLookupsExtrinsicEntry>,
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsicEntry {
    service_index: Address,
    preimage_data: Octets,
}
