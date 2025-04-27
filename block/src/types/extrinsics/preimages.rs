use crate::types::extrinsics::{XtEntry, XtType};
use rjam_codec::prelude::*;
use rjam_common::{Octets, ServiceId};
use std::ops::Deref;

/// Represents a sequence of preimage lookups, where each lookup corresponds to
/// a requested piece of data (preimage) that has been solicited by a service
/// but has not yet been provided.
#[derive(Debug, Clone, Default, PartialEq, Eq, JamEncode, JamDecode)]
pub struct PreimagesXt {
    pub items: Vec<PreimagesXtEntry>,
}

impl Deref for PreimagesXt {
    type Target = Vec<PreimagesXtEntry>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl PreimagesXt {
    pub fn total_preimage_data_len(&self) -> usize {
        self.iter().map(|entry| entry.preimage_data_len()).sum()
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Hash)]
pub struct PreimagesXtEntry {
    /// The service that requested the preimage data to be available on-chain.
    pub service_id: ServiceId,
    /// The preimage data blob.
    pub preimage_data: Octets,
}

impl XtEntry for PreimagesXtEntry {
    const XT_TYPE: XtType = XtType::PreimageLookup;
}

impl JamEncode for PreimagesXtEntry {
    fn size_hint(&self) -> usize {
        4 + self.preimage_data.size_hint()
    }

    fn encode_to<T: JamOutput>(&self, dest: &mut T) -> Result<(), JamCodecError> {
        self.service_id.encode_to_fixed(dest, 4)?; // TODO: check - Not fixed encoding in GP
        self.preimage_data.encode_to(dest)?;
        Ok(())
    }
}

impl JamDecode for PreimagesXtEntry {
    fn decode<I: JamInput>(input: &mut I) -> Result<Self, JamCodecError>
    where
        Self: Sized,
    {
        Ok(Self {
            service_id: ServiceId::decode_fixed(input, 4)?,
            preimage_data: Octets::decode(input)?,
        })
    }
}

impl PreimagesXtEntry {
    pub fn preimage_data_len(&self) -> usize {
        self.preimage_data.len()
    }
}
