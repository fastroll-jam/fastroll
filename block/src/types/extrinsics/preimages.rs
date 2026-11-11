use crate::types::extrinsics::{ExtrinsicsError, XtEntry, XtType};
use fr_codec::prelude::*;
use fr_common::{Octets, ServiceId};
use fr_crypto::hash::{hash, Blake2b256};
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

    /// Encodes the entries as `(E_4(s), H(d))` pairs, which the extrinsic hash commits to instead of the data blobs.
    pub fn encode_with_hashed_preimages(&self) -> Result<Vec<u8>, ExtrinsicsError> {
        let mut buf = vec![];
        self.items.len().encode_to(&mut buf)?; // length discriminator
        for entry in &self.items {
            entry.service_id.encode_to_fixed(&mut buf, 4)?;
            hash::<Blake2b256>(&entry.preimage_data)?.encode_to(&mut buf)?;
        }
        Ok(buf)
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, PartialEq, Eq, Hash)]
pub struct PreimagesXtEntry {
    /// `s`: The service that requested the preimage data to be available on-chain.
    pub service_id: ServiceId,
    /// **`d`**: The preimage data blob.
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
        self.service_id.encode_to_fixed(dest, 4)?;
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
