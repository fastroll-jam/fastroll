use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, Octets};
use std::ops::Deref;

/// # Ordering and Validation Rules for Extrinsic Components
/// - `items` must be ordered by `service_index` of each entry.
/// - `items` must have no duplicate entries.
#[derive(Debug, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsic {
    items: Vec<PreimageLookupsExtrinsicEntry>,
}

impl Deref for PreimageLookupsExtrinsic {
    type Target = Vec<PreimageLookupsExtrinsicEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl PreimageLookupsExtrinsic {
    pub fn total_preimage_data_len(&self) -> usize {
        self.iter().map(|entry| entry.preimage_data_len()).sum()
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsicEntry {
    service_index: Address,
    preimage_data: Octets,
}

impl PreimageLookupsExtrinsicEntry {
    pub fn preimage_data_len(&self) -> usize {
        self.preimage_data.len()
    }
}
