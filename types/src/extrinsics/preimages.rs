use rjam_codec::{JamCodecError, JamDecode, JamEncode, JamInput, JamOutput};
use rjam_common::{Address, Octets};
use std::ops::Deref;

/// Represents a sequence of preimage lookups, where each lookup corresponds to
/// a requested piece of data (preimage) that has been solicited by a service
/// but has not yet been provided.
#[derive(Debug, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsic {
    pub items: Vec<PreimageLookupsExtrinsicEntry>,
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

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Hash, JamEncode, JamDecode)]
pub struct PreimageLookupsExtrinsicEntry {
    pub service_index: Address, // requester of the preimage data
    pub preimage_data: Octets,
}

impl PreimageLookupsExtrinsicEntry {
    pub fn preimage_data_len(&self) -> usize {
        self.preimage_data.len()
    }
}
